fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().any(|arg| arg == "--print-build-info") {
        println!("{}", honey_node::runtime::current_build_info_json());
        return Ok(());
    }

    let args = honey_node::runtime::parse_node_args();
    honey_node::runtime::run_node(args).map_err(|message| std::io::Error::other(message).into())
}
