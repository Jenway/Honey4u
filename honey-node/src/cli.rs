use crate::driver_node::args::NodeRuntimeArgs;
use clap::Parser;

pub(crate) fn parse_args() -> NodeRuntimeArgs {
    NodeRuntimeArgs::parse()
}
