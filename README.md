> **Note**: this demo is featured as a [blog post][blog] at [Kong][kong].

[blog]:https://konghq.com/blog/writing-an-ebpf-xdp-load-balancer-in-rust
[kong]:https://konghq.com

# eBPF Rust UDP LoadBalancer Demo

This is an example of creating a [UDP][udp] load-balancer in [Rust][rust] as an
[eXpress Data Path (XDP)][xdp] type [eBPF][ebpf] program using the [aya][aya]
framework.

> **Note** This example assumes a fairly strong understanding of Linux,
> networking, and Rust programming.

> **Warning** At the time of writing Aya is not a mature ecosystem for eBPF
> development. This demonstration is missing several things you would want for
> a production XDP program, and Aya itself is subject to significant change in
> the time between now and it's first `v1` release. This is for demonstration
> and learning purposes only, **do not use in production**.

[udp]:https://www.cloudflare.com/learning/ddos/glossary/user-datagram-protocol-udp/
[rust]:https://www.rust-lang.org/
[xdp]:https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/
[ebpf]:https://ebpf.io/
[aya]:https://github.com/aya-rs/aya

## Background

In today's cloud ecosystem the demands for high functioning and high performance
observability, security and networking functionality for applications and their
network traffic are as high as ever. Historically a great deal of this kind of
functionality has been implemented in [userspace][userspace], but the ability
to program these kinds of things directly into the operating system can be very
beneficial to performance. The operating system has been a very challenging
place to dynamically add functionality in the past, often requiring the
development and management of very cumbersome [kernel modules][kmod], but in
recent years [eBPF][ebpf] has become a burgeoning technology in the [Linux
Kernel][linux] which is changing all that.

eBPF is a simple and efficient way to dynamically load programs into the kernel
at runtime, with safety and performance provided by the kernel itself using a
Just-In-Time (JIT) compiler and verification process. There are a variety of
different types of programs one can create with eBPF, but for the purposes of
this example we're going to focus on creating an [XDP][xdp] program which can
read and modify network packets.

Our goal is to build a small program that will load-balance ingress [UDP][udp]
traffic by port across multiple backend servers. Once you've completed this
exercise, you should have a better understanding of how XDP programs work and be
able to start your journey into the [eBPF community][ebpf-com].

> **Note** Looking for more information on eBPF in general? Check out the [What
> is eBPF][ebpf-what] documentation.

[userspace]:https://en.wikipedia.org/wiki/User_space_and_kernel_space
[kmod]:https://wiki.archlinux.org/title/Kernel_module
[ebpf]:https://ebpf.io/
[linux]:https://kernel.org
[xdp]:https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/
[udp]:https://www.cloudflare.com/learning/ddos/glossary/user-datagram-protocol-udp/
[ebpf-com]:https://ebpf.io/contribute
[ebpf-what]:https://ebpf.io/what-is-ebpf/

## Prerequisites

* A [Linux][linux] system with Kernel `5.8.0`+

> **Note** This demo was built and tested on an `x86_64` machine using [Arch
> Linux][archlinux] with kernel version `5.19.11` and on [Ubuntu][ubuntu]
> `22.04.1`. It would be expected to work on most modern Linux distributions.
> If you're having problems or if you're using BSD, Mac, Windows, e.t.c. it may
> be simplest to deploy Linux in a [Virtual Machine][vm].

[linux]:https://kernel.org
[archlinux]:https://archlinux.org/
[ubuntu]:https://ubuntu.com/
[vm]:https://wikipedia.org/wiki/Virtual_machine

## Install Build Tools

To get started we will need some tools to aid in building and testing our code.

If running on Arch Linux, install the following packages:

```console
$ sudo pacman -Sy base-devel sudo netcat rustup git bpf
```

Alternatively if you're on Ubuntu:

```console
$ sudo apt install build-essential sudo netcat git bpftool
$ export PATH=/usr/sbin:$PATH
```

> **Note** the `PATH` update above is needed on Ubuntu as default users do not
> always have `/usr/sbin` in their path and this is where tools like `bpftool`
> will be installed (which are needed for building your XDP program).

> **Note** Ubuntu doesn't have `rustup` in the default repositories at the time
> of writing: you'll need to [install it manually][rustup].

[rustup]:https://www.rust-lang.org/learn/get-started

## Setup Rust Build Environment

For this project we'll need both a `stable` and a `nightly` version of the Rust
compiler. We'll also need to install a few Rust build tools.

Install and set `stable` Rust as your default:

```console
$ rustup default stable
```

Install `nightly` and it's sources so that it's available as well (this will
be needed to build the part of our program which gets loaded into the kernel):

```console
$ rustup toolchain add nightly
$ rustup component add rust-src --toolchain nightly
```

To scaffold our project, we'll need to install `cargo-generate`:

```console
$ cargo install cargo-generate
```

The `bpf-linker` program will be required so that our XDP program can be built
and loaded into the Linux kernel properly:

```console
$ cargo install bpf-linker
```

Finally, `bindgen` will need to be installed for `C` code bindings in Rust:

```console
$ cargo install bindgen-cli
```

## Scaffolding our project

[Aya][aya] provides a [template][aya-tmpl] for `cargo` which can be used to
scaffold a new XDP program and provide a lot of the code right out-of-the-box.
On your system in a directory where you'd like the code to be located, run the
following to create a new sub-directory called `demo/` which will be our project
home:

```console
$ cargo generate --name demo -d program_type=xdp https://github.com/aya-rs/aya-template
```

> **Note** in the future if you want to create a BPF program type other than
> XDP you can run without the `-d program_type=xdp` argument to get an
>interactive setup.

You'll find that several directories and files were created:

```console
$ cd demo
$ tree
.
├── Cargo.toml
├── README.md
├── demo
│   ├── Cargo.toml
│   └── src
│       └── main.rs
├── demo-common
│   ├── Cargo.toml
│   └── src
│       └── lib.rs
├── demo-ebpf
│   ├── Cargo.toml
│   ├── rust-toolchain.toml
│   └── src
│       └── main.rs
└── xtask
    ├── Cargo.toml
    └── src
        ├── build_ebpf.rs
        ├── main.rs
        └── run.rs
```

Each of these directories contains different parts of your project:

- `demo-ebpf` the XDP eBPF code that will be loaded into the kernel
- `demo` the userspace program which will load and initialize the eBPF program
- `demo-common` shared code between the kernel and userspace code
- `xtask` build and run tooling

The template provided us with a very basic (but functional) XDP program which
you can build and run. By default this will try to target `eth0`, but for the
purposes of our demo we'll use the `lo` interface (loopback/localhost) as most
systems conventionally have this interface by default (whereas the names of
other interfaces may vary).

Update the file `demo/src/main.rs` and change the default `iface` from `eth0`
to `lo`:

```diff
 #[derive(Debug, Parser)]
 struct Opt {
-    #[clap(short, long, default_value = "eth0")]
+    #[clap(short, long, default_value = "lo")]
     iface: String,
 }
```

Once this is done, we can test the provided template program:

```console
$ RUST_LOG=info cargo xtask run
[2022-09-27T16:19:41Z INFO  demo] Waiting for Ctrl-C...
```

In another terminal on the same host you can trigger this program by sending
any data to the `lo` interface, e.g.:

```console
$ echo "test" | nc 127.0.0.1 8080
```

In the `cargo xtask run` terminal, you should see the program has reported some
packets that's it's processed:

```console
$ RUST_LOG=info cargo xtask run
[2022-09-27T16:23:10Z INFO  demo] Waiting for Ctrl-C...
[2022-09-27T16:24:24Z INFO  demo] received a packet
[2022-09-27T16:24:24Z INFO  demo] received a packet
```

Once you're seeing the `received a packet` message it's working and we can move
on to adding our own packet processing logic.

[aya]:https://github.com/aya-rs/aya
[aya-tmpl]:https://github.com/aya-rs/aya-template

## Codegen for Linux types

> **Note**: in this section we are going to use a generator to create bindings
> to required types in `C` that we need to inspect packets. However at the time
> of writing the `aya` maintainers were actively working on a new crate that
> would take care of this for you instead, so if you're reading this some time
> after it's published just keep in mind this is no longer the canonical way to
> do this.

Before we add our own logic we need our Rust code to be able to speak the `C`
types that the Kernel provides to our XDP program. Aya provides a simple way
to generate Rust code for these types from `/sys/kernel/btf/vmlinux`. We'll
add a new task to our `xtask` module which uses the `aya_tool` package to
generate the code.

Create the file `xtask/src/codegen.rs`:

```rust
use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("demo-ebpf/src");
    let names: Vec<&str> = vec!["ethhdr", "iphdr", "udphdr"];
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
```

You'll need to load the codegen code in `xtask/src/main.rs`:

```diff
 mod build_ebpf;
+mod codegen;
 mod run;

 use std::process::exit;
```

```diff
 enum Command {
     BuildEbpf(build_ebpf::Options),
     Run(run::Options),
+    Codegen,
 }

 fn main() {
```

```diff
     let ret = match opts.command {
         BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
         Run(opts) => run::run(opts),
+        Codegen => codegen::generate(),
     };

     if let Err(e) = ret {
```

And the `aya_tool` dependency will need to be added to `xtask/Cargo.toml`:

```diff
 [dependencies]
 anyhow = "1"
 clap = { version = "3.1", features = ["derive"] }
+aya-tool = { git = "https://github.com/aya-rs/aya", branch = "main" }
```

With that in place, you can run the generators:

```console
$ cargo xtask codegen
```

This will emit a file named `demo-ebpf/src/bindings.rs` which contains
relevant `C` types that will be needed to process packets in the upcoming
sections.

## Processing UDP Packets

Now that you have the types generated that are needed to inspect packets, let's
open our `demo-ebpf/src/main.rs` file up in an editor, and navigate to the
`try_demo` function:

```rust
fn try_demo(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}
```

As you saw in our testing earlier, this is the code that was executed whenever a
packet was received on the `lo` interface. The result was simply the emission of
a `received a packet` message and then the packet was passed back to the kernel.

Next we're going to inspect the packet and find important datapoints (such as
the relevant protocols being used) so that we can filter out anything that
isn't a UDP packet.

We will need to import some of our code generated in the previous step, and
we'll define some `const`s which will help us navigate the memory space of the
`XdpContext` object we receive on each instantiation. Add these to your
`demo-ebpf/src/main.rs` file:

```rust
mod bindings;
use bindings::{ethhdr, iphdr, udphdr};
use core::mem;

const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
```

> **Note**: similar to the codegen tools in the previous section, new crates
> are being actively developed at the time of writing which will include
> constants like `IPPROTO_UDP` and `ETH_P_IP` for you.

We'll add some helper functions which will make it easy to handle
_raw pointers_, which will be needed to inspect the packet. Add these to your
`demo-ebpf/src/main.rs` file as well:

```rust
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}
```

> **Note**: using the raw pointers provided by the above functions will require
> the `unsafe` keyword in Rust as accessing the memory of the `XdpContext` this
> way inherently is not covered by [Rust's safety guarantees][rust-safe]. If
> you are not familiar with [unsafe Rust][rust-unsafe] then it would be highly
> recommended to pause here and read the [Unsafe Rust Book][unsafe-rust-book]
> to familiarize yourself.

Now back within our `try_demo` function we'll be able to start decoding the
memory of the `XdpContext` object we're being passed by the kernel.

We'll start by pulling the ethernet header, and checking whether the packet
we're receiving is actually an IP packet or not. Add the following to the
`try_demo` function in `demo-ebpf/src/main.rs`:

```diff
 fn try_demo(ctx: XdpContext) -> Result<u32, u32> {
     info!(&ctx, "received a packet");
+
+    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
+
+    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
+        return Ok(xdp_action::XDP_PASS);
+    }
+
     Ok(xdp_action::XDP_PASS)
 }

```

> **Note**: note the use of `unsafe` here as alluded to above. At this point in
> `aya`'s lifecycle raw pointers and direct memory access will be needed,
> particularly within the XDP program itself. This isn't ideal, but we'll still
> be getting [Rust's memory safety guarantees][rust-safe] elsewhere
> (particularly our userspace code) and also the BPF loading process in Linux
> includes memory safety checks for our XDP code for additional safety.

In the above we've added a check to tell whether or not we're dealing with an
IP packet (and if _not_ we simply pass control back to the kernel). Next since
going forward we know we will be dealing with an IP packet we'll decode the IP
header from the packet and check whether or not the protocol being used is UDP:

```diff
         return Ok(xdp_action::XDP_PASS);
     }

+    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
+
+    if unsafe { (*ip).protocol } != IPPROTO_UDP {
+        return Ok(xdp_action::XDP_PASS);
+    }
+
+    info!(&ctx, "received a UDP packet");
+
     Ok(xdp_action::XDP_PASS)
 }
```

Lastly we'll decode the UDP header and check the port that the packet is coming
in on:

```diff
     info!(&ctx, "received a UDP packet");

+    let udp = ptr_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
+
+    let destination_port = unsafe { u16::from_be((*udp).dest) };
+
+    if destination_port == 9875 {
+        info!(&ctx, "received UDP on port 9875");
+    }
+
     Ok(xdp_action::XDP_PASS)
 }

```

With this our program should be reporting on any UDP packets sent to port
`9875`. We can test this with the following:

```console
$ RUST_LOG=info cargo xtask run
[2022-09-27T17:34:28Z INFO  demo] Waiting for Ctrl-C...
```

Now in another terminal on the same system send data via UDP on port `9875`:

```console
$ echo "test" | nc -u 127.0.0.1 9875
```

If everything is working properly, your program in should inform you of the
ingress packet:

```console
$ RUST_LOG=info cargo xtask run
[2022-09-27T17:34:28Z INFO  demo] Waiting for Ctrl-C...
[2022-09-27T17:35:36Z INFO  demo] received a packet
[2022-09-27T17:35:36Z INFO  demo] received a UDP packet
[2022-09-27T17:35:36Z INFO  demo] received UDP on port 9875
[2022-09-27T17:35:36Z INFO  demo] received a packet
```

> **Note**: if you're wondering what the packet at the end of the log is (since
> it doesn't get reported as UDP) that is an ICMP response back to us to let us
> know that the port isn't available for the UDP traffic as we don't have any
> server listening on that port yet, so the kernel simply refused it.

Now we know how to decode information from the `XdpPacket`, next we'll try
_modifying the packet_ to change the flow of traffic.

[rust-safe]:https://developer.okta.com/blog/2022/03/18/programming-security-and-why-rust
[rust-unsafe]:https://doc.rust-lang.org/std/keyword.unsafe.html
[unsafe-rust-book]:https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html

## Port Redirection

Now that we understand how to inspect UDP packets in our XDP program, we'll
try modifying the port to send packets meant for `9875` to a different port
(`9876`).

Before we make changes to our XDP program to support this, we'll take a second
to add a small UDP listen server which will help us to illustrate our tests.

Update the `Cargo.toml` file to include a new `demo-server` directory in our
workspace:

```diff
 [workspace]
-members = ["demo", "demo-common", "xtask"]
+members = ["demo", "demo-common", "demo-server", "xtask"]
```

Create the relevant directories:

```console
$ mkdir -p demo-server/src/
```

Add a `demo-server/Cargo.toml` for the new crate:

```toml
[package]
name = "server"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
```

Then add the programs `demo-server/src/main.rs`:

```rust
use std::io;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let wait = vec![
        tokio::spawn(run_server(9876)),
        tokio::spawn(run_server(9877)),
        tokio::spawn(run_server(9878)),
    ];

    for t in wait {
        t.await.expect("server failed").unwrap();
    }
}

async fn run_server(port: u16) -> io::Result<()> {
    let bindaddr = format!("127.0.0.1:{}", port);
    let sock = UdpSocket::bind(&bindaddr).await?;
    println!("listening on {}", bindaddr);

    let mut buf = [0; 4];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("port {}: {} bytes received from {}", port, len, addr);
        println!(
            "port {}: buffer contents: {}",
            port,
            String::from_utf8_lossy(&buf)
        );
    }
}
```

This program will listen on ports `9876`, `9877` and `9878` for UDP data and
print the contents and information about them to `STDOUT`, including which
specific port the data came in on. This is meant to emulate different backends
which we will eventually be load-balancing traffic to.

You can test the program by running the following:

```console
$ cargo run --bin server
listening on 127.0.0.1:9876
listening on 127.0.0.1:9877
listening on 127.0.0.1:9878
```

In another terminal on the same system, send data to any of them:

```console
$ echo "test" | nc -u 127.0.0.1 9878
```

If everything is working properly, you should see an update from the server
program:

```console
$ cargo run --bin server
listening on 127.0.0.1:9876
listening on 127.0.0.1:9877
listening on 127.0.0.1:9878
port 9878: 5 bytes received from 127.0.0.1:54985
port 9878: buffer contents: test
```

Now we're ready to upgrade our simple port redirect to a load-balancer which
distributes UDP traffic between these three ports.

## Routing rules with BPF maps

The kernel provides [maps][ebpf-maps] in BPF programs as a means for userspace
programs to communicate with the underlying XDP program, and visa versa.

To allow the userspace program to inform the XDP program as to which backend
ports traffic should be distributed to, we will create a `BackendPorts`
data-structure in `demo-common/src/lib.rs`:

```rust
#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendPorts {
    pub ports: [u16; 4],
    pub index: usize,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendPorts {}
```

> **Note**: The structs that you create for BPF maps will need to be memory
> aligned to the value of `mem::align_of::<u32>()` (commonly, `4`), and have no
> padding. In the above example this is already accounted for, but in the future
> when you create maps with `aya` you'll need to keep this in mind or the BPF
> verifier will refuse to load your code with `invalid indirect read from stack`.
> See the [documentation in the aya book regarding "Alignment, padding and
> verifier errors"][aya-book] for more information.

We'll store `BackendPorts` in a `HashMap` where the _key_ is the frontend port
and the _value_ is the `BackendPorts` object which includes a list of all the
available ports for sending traffic and an index which allows us to provide
round-robin style load-balancing.

We'll add a dependency on the newer version of `aya` so that we have access
to the `bpf::bindings` module. Add the dependency to `demo/Cargo.toml`:

```diff
 [dependencies]
 aya = { version = ">=0.11", features=["async_tokio"] }
+aya-bpf = { git = "https://github.com/aya-rs/aya", branch = "main" }
 aya-log = "0.1"
 demo-common = { path = "../demo-common", features=["user"] }
 anyhow = "1.0.42"
```

Next we'll update our XDP program to initialize a map when loaded into the
Kernel. This map will associate the inbound destination port (as the map key)
with the `Backends` for that port (as the map value). We'll need to add the
following uses first to our `demo-ebpf/src/main.rs` file:

```diff
 use aya_bpf::{
     bindings::xdp_action,
-    macros::xdp,
+    macros::{map, xdp},
+    maps::HashMap,
     programs::XdpContext,
 };
 use aya_log_ebpf::info;
+use demo_common::BackendPorts;
```

Then add the map itself to the same file:

```rust
#[map(name = "BACKEND_PORTS")]
static mut BACKEND_PORTS: HashMap<u16, BackendPorts> =
    HashMap::<u16, BackendPorts>::with_max_entries(10, 0);
```

Our userspace program will populate the map with routing data, so we'll need to
update that as well. Add some uses to `demo/src/main.rs`:

```diff
 use anyhow::Context;
+use aya::maps::HashMap;
 use aya::programs::{Xdp, XdpFlags};
 use aya::{include_bytes_aligned, Bpf};
 use aya_log::BpfLogger;
 use clap::Parser;
+use demo_common::BackendPorts;
 use log::{info, warn};
 use tokio::signal;
```

And then add the following code underneath the `program.attach` call to load
the BPF map with data the XDP program can use to route traffic:

```rust
let mut backends: HashMap<_, u16, BackendPorts> =
    HashMap::try_from(bpf.map_mut("BACKEND_PORTS")?)?;

let mut ports: [u16; 4] = [0; 4];
ports[0] = 9876;
ports[1] = 9877;
ports[2] = 9878;

let backend_ports = BackendPorts { ports, index: 0 };

backends.insert(9875, backend_ports, 0)?;
```

[ebpf-maps]:https://www.kernel.org/doc/html/latest/bpf/maps.html
[aya-com]:https://aya-rs.dev/community/
[aya-book]:https://aya-rs.dev/

## Enable Load-Balancing

With our `Backends` map in place we're now in a position to use it to
dynamically distribute incoming UDP traffic. Update the the `try_demo` function
in `demo-ebpf/src/main.rs` to look like this:

```rust
fn try_demo(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");

    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;

    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "received a UDP packet");

    let udp = ptr_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;

    let destination_port = unsafe { u16::from_be((*udp).dest) };

    let backends = match unsafe { BACKEND_PORTS.get(&destination_port) } {
        Some(backends) => {
            info!(&ctx, "FOUND backends for port");
            backends
        }
        None => {
            info!(&ctx, "NO backends found for this port");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if backends.index > backends.ports.len() - 1 {
        return Ok(xdp_action::XDP_ABORTED);
    }
    let new_destination_port = backends.ports[backends.index];
    unsafe { (*udp).dest = u16::from_be(new_destination_port) };

    info!(
        &ctx,
        "redirected port {} to {}", destination_port, new_destination_port
    );

    let mut new_backends = BackendPorts {
        ports: backends.ports,
        index: backends.index + 1,
    };

    if new_backends.index > new_backends.ports.len() - 1
        || new_backends.ports[new_backends.index] == 0
    {
        new_backends.index = 0;
    }

    match unsafe { BACKEND_PORTS.insert(&destination_port, &new_backends, 0) } {
        Ok(_) => {
            info!(&ctx, "index updated for port {}", destination_port);
            Ok(xdp_action::XDP_PASS)
        }
        Err(err) => {
            info!(&ctx, "error inserting index update: {}", err);
            Ok(xdp_action::XDP_ABORTED)
        }
    }
}
```

In the above we retrieve the `Backends` for any incoming traffic by that
traffics destination port (if any), update the destination port in the packet,
and then update the backends index so that the next packet will reach one of
the other ports, then we pass the packet back to the kernel.

> **Note**: For brevity some things were left out of this demo, such as
> updating the IP and UDP header checksums for modified packets. For this demo
> they weren't required, but if you take your learning further you'll need to
> update your packet checksums. See the [Aya Documentation][aya-docs] for more
> information.

You can now run your programs:

```console
$ RUST_LOG=info cargo xtask run
```

And in another terminal, start the UDP listen server:

```console
$ cargo run --bin server
listening on 127.0.0.1:9876
listening on 127.0.0.1:9877
listening on 127.0.0.1:9878
```

And in one final terminal, send UDP data to port `9875` multiple times:

```console
$ echo "test" | nc -u 127.0.0.1 9875
$ echo "test" | nc -u 127.0.0.1 9875
$ echo "test" | nc -u 127.0.0.1 9875
```

> **Note**: you'll need to `CTRL+c` in between each of these commands

If everything worked properly, the UDP server should show that the traffic was
being distributed across each of the ports:

```console
$ cargo run --bin server
listening on 127.0.0.1:9876
listening on 127.0.0.1:9877
listening on 127.0.0.1:9878

port 9876: 5 bytes received from 127.0.0.1:37480
port 9876: buffer contents: test

port 9877: 5 bytes received from 127.0.0.1:57018
port 9877: buffer contents: test

port 9878: 5 bytes received from 127.0.0.1:35574
port 9878: buffer contents: test
```

And that's it! You've now created a simple demonstration load-balancer that
distributes UDP traffic for a given port to a number of backends.

[aya-book]:https://aya-rs.dev/book/start/logging-packets/#sharing-data
[aya-docs]:https://docs.aya-rs.dev/

## Next Steps

At this point you should understand how to start a new XDP project with `aya`,
and the basics of how to read and manipulate information in network packets
processed by your XDP program. From here you should be able to experiment
further with things like adding more criteria for routing packets (such as
source and destination IP) as well as manipulating the destination IP. Make sure
to read the [Aya Book][aya-book] for more XDP examples, and even examples of
other types of eBPF programs you can try out. Keep in mind that **this example
is not intended to be used as a basis for a production implementation**. Happy
coding!

[aya-book]:https://aya-rs.dev/book/

## Extra Notes

The following are some extra notes which were not specifically relevant to this
demo, but may be of interest as you explore further.

### Further Reading: Awesome Aya!

> **Note**: For other blog posts, demos and projects using Aya, check out the
> [Awesome Aya][aya-awesome] repository which includes a curated list of other
> tools using Aya.

[aya-awesome]:https://github.com/aya-rs/awesome-aya

### Further Reading: XDP Tutorials

> **Note**: If you'd like to go beyond what you learned here, there are lots of
> extra examples and tutorials for XDP programs provided by the [XDP
> Project][xdp-proj] within their [XDP Tutorials][xdp-tuts] repository. These
> are in `C` rather than Rust at the time of writing, but should provide
> insights into how different tasks can be achieved.

[xdp-proj]:https://github.com/xdp-project/
[xdp-tuts]:https://github.com/xdp-project/xdp-tutorial

### Further Reading: Memory Safety in eBPF programs

> **Note**: For the purposes of this demo we glossed over how memory safety is
> achieved in eBPF programs. If you're interested in learning more about how
> memory is managed under the hood for maps, check out the [Linux "Read, Copy
> Update" (RCU) synchronization mechanism documentation][rcu] and reach out to
> the [Aya community][aya-com] with questions.

[rcu]:https://www.kernel.org/doc/html/latest/RCU/whatisRCU.html
[aya-com]:https://aya-rs.dev/community/

### BTF Status Support in Aya

> **Note**: at the time of writing [BPF Type Format (BTF)][btf] support is
> incomplete on the eBPF program side when using `aya`. In particular: support
> for the [Compile-Once Run-Everywhere (CO-RE)][co-re] functionality of BTF is
> [not yet fully implemented][aya-349]. Practically speaking this is not very
> relevant for XDP program, but for other programs written in `aya` it means
> they may need to be recompiled for different target systems. The maintainers
> intend to resolve this in future releases of `aya`.

[btf]:https://www.kernel.org/doc/html/latest/bpf/btf.html
[co-re]:https://github.com/cilium/ebpf/issues/114
[aya-349]:https://github.com/aya-rs/aya/issues/349

### BPF Debug Status in Aya

> **Note**: at the time of writing `aya` does not yet support [BPF Debug
> Info][aya-351]. The maintainers intend to resolve this in future releases.

[aya-351]:https://github.com/aya-rs/aya/issues/351

# License

This demo is distributed under the following licenses:

- the `README.md` is licensed under the terms of the [Creative Commons CC-BY-SA v4.0][cc] license.
- all other files are licensed under the terms of [General Public License, v2][gpl] license or [MIT License][mit] at your option.

[cc]:https://github.com/shaneutt/ebpf-rust-udp-loadbalancer-demo/blob/main/LICENSE-CC-BY-SA
[gpl]:https://github.com/shaneutt/ebpf-rust-udp-loadbalancer-demo/blob/main/LICENSE-GPL
[mit]:https://github.com/shaneutt/ebpf-rust-udp-loadbalancer-demo/blob/main/LICENSE-MIT
