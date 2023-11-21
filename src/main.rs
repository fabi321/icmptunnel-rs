use clap::{Parser, Subcommand};
use icmptunnel_rs::client::start_client;
use icmptunnel_rs::server::start_server;
use std::net::IpAddr;

#[derive(Parser, Debug)]
struct Arguments {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Client {
        #[clap(short, long)]
        /// Server address
        server_address: IpAddr,
        #[clap(short, long)]
        /// Server password
        password: String,
    },
    Server {
        #[clap(short, long)]
        /// Password for authentication
        password: String,
    },
}

fn main() {
    let arguments = Arguments::parse();
    match arguments.command {
        Commands::Server { password } => start_server(password),
        Commands::Client {
            server_address,
            password,
        } => start_client(server_address, password),
    }
}
