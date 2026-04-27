use super::super::DRIVER_NETWORK_BATCH_LIMIT;
use super::super::driver_wire::{DriverWireFrame, decode_driver_frame};
use super::super::pool_wire::{PoolFetchWire, decode_pool_fetch_from_wire};
use super::super::types::{BatchArchive, DriverCarryovers, InboundShareBundle, QueuePeaksSnapshot};
use super::batch::remember_archived_batch;
use super::pool::PendingPoolFetchRequest;
use honey_node::transport::LocalTcpTransport;
use std::collections::BTreeMap;

pub(super) fn update_queue_peaks(transport: &LocalTcpTransport, peaks: &mut QueuePeaksSnapshot) {
    let pending_inbound = transport.pending_inbound();
    let pending_outbound = transport.pending_outbound();
    peaks.raw_inbound_messages = peaks.raw_inbound_messages.max(pending_inbound);
    peaks.raw_outbound_messages = peaks.raw_outbound_messages.max(pending_outbound);
    peaks.transport_inbound = peaks.transport_inbound.max(pending_inbound);
    peaks.transport_outbound = peaks.transport_outbound.max(pending_outbound);
}

pub(super) struct RoundTransportInbox<'a> {
    pub(super) inbound_acs_wire: &'a mut Vec<Vec<u8>>,
    pub(super) pending_pool_fetch_requests: &'a mut Vec<PendingPoolFetchRequest>,
    pub(super) pending_pool_fetch_responses: &'a mut Vec<PoolFetchWire>,
    pub(super) received_batches: &'a mut BTreeMap<usize, Vec<u8>>,
    pub(super) pending_share_bundles: &'a mut Vec<InboundShareBundle>,
}

pub(super) fn drain_transport_into_round(
    transport: &LocalTcpTransport,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    batch_archive: &mut BatchArchive,
    inbox: &mut RoundTransportInbox<'_>,
) -> Result<usize, String> {
    let mut frame_count = 0usize;
    for payload in transport
        .recv_batch(DRIVER_NETWORK_BATCH_LIMIT)
        .map_err(|err| err.to_string())?
    {
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
            DriverWireFrame::HbBatch {
                sender,
                round_id: frame_round_id,
                sealed_batch,
            } => {
                remember_archived_batch(batch_archive, frame_round_id, sender, &sealed_batch);
                if frame_round_id == round_id {
                    inbox.received_batches.entry(sender).or_insert(sealed_batch);
                } else if frame_round_id > round_id {
                    carryovers
                        .sealed_batches
                        .entry(frame_round_id)
                        .or_default()
                        .entry(sender)
                        .or_insert(sealed_batch);
                }
            }
            DriverWireFrame::HbShareBundle {
                sender,
                round_id: frame_round_id,
                selected_batch_refs,
                shares,
            } => {
                let bundle = InboundShareBundle {
                    sender,
                    selected_batch_refs,
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
