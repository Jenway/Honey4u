use crate::driver::args::NodeRuntimeArgs;
use clap::Parser;

pub(crate) fn parse_args() -> NodeRuntimeArgs {
    NodeRuntimeArgs::parse()
}
