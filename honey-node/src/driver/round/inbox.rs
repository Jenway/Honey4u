use super::state::{DriverCarryovers, InboundShareBundle, QueuePeaksSnapshot};
use crate::driver::DRIVER_NETWORK_BATCH_LIMIT;
use crate::driver::error::DriverResult;
use crate::driver::frame::{
    DriverWireFrame, PoolFetchWire, decode_driver_frame, decode_pool_fetch_from_wire,
};
use crate::driver::mempool::fetch::PendingPoolFetchRequest;
use honey_transport::TransportHandle;

pub(in crate::driver) fn update_queue_peaks(
    transport: &dyn TransportHandle,
    peaks: &mut QueuePeaksSnapshot,
) {
    let pending_inbound = transport.pending_inbound();
    let pending_outbound = transport.pending_outbound();
    peaks.raw_inbound_messages = peaks.raw_inbound_messages.max(pending_inbound);
    peaks.raw_outbound_messages = peaks.raw_outbound_messages.max(pending_outbound);
    peaks.transport_inbound = peaks.transport_inbound.max(pending_inbound);
    peaks.transport_outbound = peaks.transport_outbound.max(pending_outbound);
}

pub(in crate::driver) struct RoundTransportInbox<'a> {
    pub(in crate::driver) inbound_acs_wire: &'a mut Vec<Vec<u8>>,
    pub(in crate::driver) pending_pool_fetch_requests: &'a mut Vec<PendingPoolFetchRequest>,
    pub(in crate::driver) pending_pool_fetch_responses: &'a mut Vec<PoolFetchWire>,
    pub(in crate::driver) pending_share_bundles: &'a mut Vec<InboundShareBundle>,
}

pub(in crate::driver) fn drain_transport_into_round(
    transport: &dyn TransportHandle,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    inbox: &mut RoundTransportInbox<'_>,
) -> DriverResult<usize> {
    let mut frame_count = 0usize;
    for payload in transport.recv_batch(DRIVER_NETWORK_BATCH_LIMIT)? {
        frame_count += 1;
        match decode_driver_frame(&payload)? {
            DriverWireFrame::AcsEnvelope {
                round_id: frame_round_id,
                payload,
            } => {
                if let Some(pool_message) = decode_pool_fetch_from_wire(&payload)? {
                    match pool_message {
                        request @ PoolFetchWire::Request { .. } => {
                            inbox
                                .pending_pool_fetch_requests
                                .push(PendingPoolFetchRequest {
                                    round_id: frame_round_id,
                                    message: request,
                                });
                        }
                        response @ PoolFetchWire::Response { .. } => {
                            if frame_round_id == round_id {
                                inbox.pending_pool_fetch_responses.push(response);
                            } else if frame_round_id > round_id {
                                carryovers
                                    .pool_fetch_responses
                                    .entry(frame_round_id)
                                    .or_default()
                                    .push(response);
                            }
                        }
                    }
                } else if frame_round_id == round_id {
                    inbox.inbound_acs_wire.push(payload);
                } else if frame_round_id > round_id {
                    carryovers
                        .acs_wire_payloads
                        .entry(frame_round_id)
                        .or_default()
                        .push(payload);
                }
            }
            DriverWireFrame::HbShareBundle {
                sender,
                round_id: frame_round_id,
                selected_proposal_ids,
                selected_digests,
                shares,
            } => {
                let bundle = InboundShareBundle {
                    sender,
                    selected_proposal_ids,
                    selected_digests,
                    shares,
                };
                if frame_round_id == round_id {
                    inbox.pending_share_bundles.push(bundle);
                } else if frame_round_id > round_id {
                    carryovers
                        .share_bundles
                        .entry(frame_round_id)
                        .or_default()
                        .push(bundle);
                }
            }
        }
    }
    Ok(frame_count)
}
