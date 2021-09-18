extern crate libc;

use libc::{c_char, c_int, c_uchar, c_uint, c_ushort};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::From;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::env;
use std::ffi::{CStr, CString};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::Write;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use nlmsg::{Group, Netlink, NetlinkMessage, OpenGroups, NLMSG_LENGTH, NLMSG_SPACE};

pub fn select(
    mut readfds: HashSet<RawFd>,
    mut writefds: HashSet<RawFd>,
    mut errorfds: HashSet<RawFd>,
    timeout: Option<Duration>,
) -> io::Result<(HashSet<RawFd>, HashSet<RawFd>, HashSet<RawFd>)> {
    unsafe {
        let mut tv = timeout.map(|timeout| {
            let mut tv: libc::timeval = mem::zeroed();
            tv.tv_sec = timeout.as_secs() as i64;
            tv.tv_usec = timeout.subsec_micros() as i64;
            tv
        });
        let mut rfds = match readfds.is_empty() {
            true => None,
            false => {
                let mut rfds: mem::MaybeUninit<libc::fd_set> = mem::MaybeUninit::uninit();
                libc::FD_ZERO(rfds.as_mut_ptr());
                for fd in readfds.iter() {
                    libc::FD_SET(fd.as_raw_fd(), rfds.as_mut_ptr());
                }
                Some(rfds.assume_init())
            }
        };
        let mut wfds = match writefds.is_empty() {
            true => None,
            false => {
                let mut wfds: mem::MaybeUninit<libc::fd_set> = mem::MaybeUninit::uninit();
                libc::FD_ZERO(wfds.as_mut_ptr());
                for fd in writefds.iter() {
                    libc::FD_SET(fd.as_raw_fd(), wfds.as_mut_ptr());
                }
                Some(wfds.assume_init())
            }
        };
        let mut efds = match errorfds.is_empty() {
            true => None,
            false => {
                let mut efds: mem::MaybeUninit<libc::fd_set> = mem::MaybeUninit::uninit();
                libc::FD_ZERO(efds.as_mut_ptr());
                for fd in errorfds.iter().cloned() {
                    libc::FD_SET(fd, efds.as_mut_ptr());
                }
                Some(efds.assume_init())
            }
        };
        let nfds = readfds
            .iter()
            .chain(writefds.iter())
            .chain(errorfds.iter())
            .max()
            .map_or(0, |max| max + 1);
        let tv = tv.as_mut().map_or_else(ptr::null_mut, |v| v);
        let rfds = rfds.as_mut().map_or_else(ptr::null_mut, |v| v);
        let wfds = wfds.as_mut().map_or_else(ptr::null_mut, |v| v);
        let efds = efds.as_mut().map_or_else(ptr::null_mut, |v| v);
        if 0 > libc::select(nfds, rfds, wfds, efds, tv) {
            return Err(io::Error::last_os_error());
        }
        if !rfds.is_null() {
            readfds.retain(|fd| libc::FD_ISSET(fd.as_raw_fd(), rfds));
        }
        if !wfds.is_null() {
            writefds.retain(|fd| libc::FD_ISSET(fd.as_raw_fd(), wfds));
        }
        if !efds.is_null() {
            errorfds.retain(|fd| libc::FD_ISSET(fd.as_raw_fd(), efds));
        }
        Ok((readfds, writefds, errorfds))
    }
}

// include/linux/netlink.h
pub mod nlmsg {
    use libc::nlmsghdr;
    use std::fmt;
    use std::io;
    use std::mem;
    use std::ops::{Deref, DerefMut};
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
    use std::slice;

    pub const NLMSG_ALIGNTO: usize = 4;

    #[allow(non_snake_case)]
    pub const fn NLMSG_ALIGN(len: usize) -> usize {
        (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
    }

    pub const NLMSG_HDRLEN: usize = NLMSG_ALIGN(mem::size_of::<nlmsghdr>());

    #[allow(non_snake_case)]
    pub const fn NLMSG_LENGTH(len: usize) -> usize {
        len + NLMSG_ALIGN(NLMSG_HDRLEN)
    }

    #[allow(non_snake_case)]
    pub const fn NLMSG_SPACE(len: usize) -> usize {
        NLMSG_ALIGN(NLMSG_LENGTH(len))
    }

    #[allow(non_snake_case)]
    pub unsafe fn NLMSG_DATA(nlh: *const nlmsghdr) -> *const u8 {
        nlh.cast::<u8>().add(NLMSG_LENGTH(0))
    }

    #[allow(non_snake_case)]
    pub unsafe fn NLMSG_DATA_MUT(nlh: *mut nlmsghdr) -> *mut u8 {
        nlh.cast::<u8>().add(NLMSG_LENGTH(0))
    }

    #[allow(non_snake_case)]
    pub const fn NLMSG_PAYLOAD<T>(nlh: &nlmsghdr) -> usize {
        nlh.nlmsg_len as usize - NLMSG_SPACE(mem::size_of::<T>())
    }

    #[repr(C)]
    pub struct NetlinkMessage(libc::nlmsghdr);

    impl NetlinkMessage {
        pub fn as_ptr(&self) -> *const nlmsghdr {
            &self.0 as *const _
        }

        pub fn as_mut_ptr(&mut self) -> *mut nlmsghdr {
            &mut self.0 as *mut _
        }

        pub fn get_data_unchecked<T>(&self) -> &T {
            unsafe { &*NLMSG_DATA(self.as_ptr()).cast() }
        }

        pub fn get_data_mut_unchecked<T>(&mut self) -> &mut T {
            unsafe { &mut *NLMSG_DATA_MUT(self.as_mut_ptr()).cast() }
        }

        pub fn get_data<T>(&self) -> Option<&T> {
            if NLMSG_LENGTH(mem::size_of::<T>()) > self.nlmsg_len as _ {
                return None;
            }
            Some(self.get_data_unchecked())
        }

        pub fn get_data_mut<T>(&mut self) -> Option<&mut T> {
            if NLMSG_LENGTH(mem::size_of::<T>()) > self.nlmsg_len as _ {
                return None;
            }
            Some(self.get_data_mut_unchecked())
        }

        pub fn get_payload_uncheck<T>(&self) -> &[u8] {
            unsafe {
                slice::from_raw_parts(
                    NLMSG_DATA(self.as_ptr()).add(NLMSG_ALIGN(mem::size_of::<T>())),
                    NLMSG_PAYLOAD::<T>(self),
                )
            }
        }

        pub fn get_payload<T>(&self) -> Option<&[u8]> {
            if NLMSG_LENGTH(mem::size_of::<T>()) > self.nlmsg_len as _ {
                return None;
            }
            Some(self.get_payload_uncheck::<T>())
        }
    }

    impl Deref for NetlinkMessage {
        type Target = libc::nlmsghdr;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for NetlinkMessage {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl fmt::Debug for NetlinkMessage {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.debug_struct("nlmsghdr")
                .field("len", &self.nlmsg_len)
                .field("type", &self.nlmsg_type)
                .field("flags", &self.nlmsg_flags)
                .field("seq", &self.nlmsg_seq)
                .field("pid", &self.nlmsg_pid)
                .finish()
        }
    }

    #[derive(Debug)]
    pub struct Iter<'a> {
        slice: &'a [u8],
        pos: usize,
    }

    impl<'a> Iter<'a> {
        pub fn new(src: &'a [u8]) -> Self {
            Self { slice: src, pos: 0 }
        }
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = &'a NetlinkMessage;

        fn next(&mut self) -> Option<Self::Item> {
            unsafe {
                let slice = &self.slice[self.pos..];
                let len = slice.len();
                if mem::size_of::<NetlinkMessage>() > len {
                    return None;
                }
                let nlh: &NetlinkMessage = &*slice.as_ptr().cast();
                if len < nlh.nlmsg_len as _ {
                    return None;
                }
                self.pos += NLMSG_ALIGN(nlh.nlmsg_len as usize);
                Some(nlh)
            }
        }
    }

    pub struct IntoNetlinkMessage {
        vec: Vec<u8>,
    }

    impl IntoNetlinkMessage {
        pub unsafe fn new_unchecked<T>(vec: T) -> Self
        where
            T: Into<Vec<u8>>,
        {
            let vec = vec.into();
            Self { vec }
        }
        pub fn new<T>(vec: T) -> Option<Self>
        where
            T: Into<Vec<u8>>,
        {
            let vec = vec.into();
            match Iter::new(&vec).next() {
                Some(_) => unsafe { Some(Self::new_unchecked(vec)) },
                None => None,
            }
        }

        pub fn as_nlmsg<'a>(&'a self) -> &'a NetlinkMessage {
            Iter::new(&self.vec).next().unwrap()
        }
    }

    impl Deref for IntoNetlinkMessage {
        type Target = NetlinkMessage;

        fn deref(&self) -> &Self::Target {
            self.as_nlmsg()
        }
    }

    impl fmt::Debug for IntoNetlinkMessage {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            self.as_nlmsg().fmt(fmt)
        }
    }

    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
    pub enum Group {
        NONE,
        LINK,
        NOTIFY,
        NEIGH,
        TC,
        IPV4_IFADDR,
        IPV4_MROUTE,
        IPV4_ROUTE,
        IPV4_RULE,
        IPV6_IFADDR,
        IPV6_MROUTE,
        IPV6_ROUTE,
        IPV6_IFINFO,
        DECnet_IFADDR,
        DECnet_ROUTE,
        IPV6_PREFIX,
    }

    impl Group {
        pub fn get(&self) -> u32 {
            match self {
                Group::NONE => 0,
                Group::LINK => 1,
                Group::NOTIFY => 2,
                Group::NEIGH => 3,
                Group::TC => 4,
                Group::IPV4_IFADDR => 5,
                Group::IPV4_MROUTE => 6,
                Group::IPV4_ROUTE => 7,
                Group::IPV4_RULE => 8,
                Group::IPV6_IFADDR => 9,
                Group::IPV6_MROUTE => 10,
                Group::IPV6_ROUTE => 11,
                Group::IPV6_IFINFO => 12,
                Group::DECnet_IFADDR => 13,
                Group::DECnet_ROUTE => 14,
                Group::IPV6_PREFIX => 15,
            }
        }
    }

    fn group_to_mask(group: &Group) -> Option<u32> {
        match group {
            Group::LINK => Some(1),
            Group::NOTIFY => Some(2),
            Group::NEIGH => Some(4),
            Group::TC => Some(8),
            Group::IPV4_IFADDR => Some(0x10),
            Group::IPV4_MROUTE => Some(0x20),
            Group::IPV4_ROUTE => Some(0x40),
            Group::IPV4_RULE => Some(0x80),
            Group::IPV6_IFADDR => Some(0x100),
            Group::IPV6_MROUTE => Some(0x200),
            Group::IPV6_ROUTE => Some(0x400),
            Group::IPV6_IFINFO => Some(0x800),
            Group::DECnet_IFADDR => Some(0x1000),
            Group::DECnet_ROUTE => Some(0x4000),
            Group::IPV6_PREFIX => Some(0x20000),
            _ => None,
        }
    }

    #[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
    pub struct SubscriptionError;

    pub struct OpenGroups {
        groups: u32,
    }

    impl OpenGroups {
        pub fn new() -> Self {
            Self { groups: 0 }
        }
        pub fn subscription(&mut self, group: &Group) -> Result<bool, SubscriptionError> {
            let mask = group_to_mask(group).ok_or(SubscriptionError)?;
            if 0 == self.groups & mask {
                self.groups |= mask;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        pub fn cancel_subscription(&mut self, group: &Group) -> Result<bool, SubscriptionError> {
            let mask = group_to_mask(group).ok_or(SubscriptionError)?;
            if 0 == self.groups & mask {
                self.groups &= !mask;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        pub fn get(&self) -> u32 {
            self.groups
        }
    }

    #[derive(Debug)]
    pub struct Netlink {
        fd: libc::c_int,
    }

    impl Netlink {
        pub fn open(subscriptions: &OpenGroups) -> io::Result<Self> {
            Self::open_by_protocol(subscriptions, libc::NETLINK_ROUTE)
        }

        fn open_by_protocol(subscriptions: &OpenGroups, protocol: libc::c_int) -> io::Result<Self> {
            unsafe {
                let mut local: libc::sockaddr_nl = mem::zeroed();
                local.nl_family = libc::AF_NETLINK as u16;
                local.nl_groups = subscriptions.get();
                let fd = libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    protocol,
                );
                if 0 > fd {
                    return Err(io::Error::last_os_error());
                }
                if 0 > libc::bind(fd, mem::transmute(&local), mem::size_of_val(&local) as u32) {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self::from_raw_fd(fd))
            }
        }

        pub fn add_group(&mut self, group: Group) -> io::Result<()> {
            unsafe {
                let group = group.get();
                if 0 == libc::setsockopt(
                    self.as_raw_fd(),
                    libc::SOL_NETLINK,
                    libc::NETLINK_ADD_MEMBERSHIP,
                    &group as *const _ as *const libc::c_void,
                    mem::size_of::<u32>() as u32,
                ) {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }

        pub fn drop_group(&mut self, group: Group) -> io::Result<()> {
            unsafe {
                let group = group.get();
                if 0 == libc::setsockopt(
                    self.as_raw_fd(),
                    libc::SOL_NETLINK,
                    libc::NETLINK_DROP_MEMBERSHIP,
                    &group as *const _ as *const libc::c_void,
                    mem::size_of::<u32>() as u32,
                ) {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }

        pub fn recv(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
            unsafe {
                let mut iov: libc::iovec = mem::zeroed();
                let mut sa: libc::sockaddr_nl = mem::zeroed();
                let mut msg: libc::msghdr = mem::zeroed();
                msg.msg_name = &mut sa as *mut _ as _;
                msg.msg_namelen = mem::size_of_val(&sa) as _;
                let len = libc::recvmsg(
                    self.as_raw_fd(),
                    &mut msg as *mut _ as _,
                    libc::MSG_PEEK | libc::MSG_TRUNC,
                );
                if 0 > len {
                    return Err(io::Error::last_os_error());
                }
                let len = len as usize;
                buf.reserve(len);
                msg.msg_iov = &mut iov as *mut _ as _;
                msg.msg_iovlen = 1;
                let len = buf.len();
                iov.iov_base = buf[len..].as_mut_ptr() as _;
                iov.iov_len = buf.capacity() - buf.len();
                let len = libc::recvmsg(self.as_raw_fd(), &mut msg as *mut _ as _, 0);
                if 0 > len {
                    return Err(io::Error::last_os_error());
                }
                let len = len as usize;
                buf.set_len(buf.len() + len);
                Ok(len)
            }
        }

        pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
            let len = unsafe { libc::send(self.as_raw_fd(), buf.as_ptr().cast(), buf.len(), 0) };
            if 0 > len {
                return Err(io::Error::last_os_error());
            }
            Ok(len as usize)
        }
    }

    impl Drop for Netlink {
        fn drop(&mut self) {
            let _ = unsafe { libc::close(self.fd) };
        }
    }

    impl AsRawFd for Netlink {
        fn as_raw_fd(&self) -> RawFd {
            self.fd
        }
    }

    impl FromRawFd for Netlink {
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            Netlink { fd }
        }
    }

    impl IntoRawFd for Netlink {
        fn into_raw_fd(self) -> RawFd {
            self.fd
        }
    }
}

// include/linux/if_addr.h
#[repr(C)]
pub struct ifaddrmsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

// include/linux/rtnetlink.h
pub mod rta {
    use libc::c_ushort;
    use std::mem;
    use std::slice;

    #[repr(C)]
    pub struct rtattr {
        pub rta_len: c_ushort,
        pub rta_type: c_ushort,
    }

    pub const RTA_ALIGNTO: usize = 4;

    #[allow(non_snake_case)]
    pub const fn RTA_ALIGN(len: usize) -> usize {
        (len + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
    }

    #[allow(non_snake_case)]
    pub const fn RTA_LENGTH(len: usize) -> usize {
        RTA_ALIGN(mem::size_of::<rtattr>()) + len
    }

    #[allow(non_snake_case)]
    pub const fn RTA_SPACE(len: usize) -> usize {
        RTA_ALIGN(RTA_LENGTH(len))
    }

    #[allow(non_snake_case)]
    pub unsafe fn RTA_DATA(rta: *const u8) -> *const u8 {
        rta.add(RTA_LENGTH(0))
    }

    #[allow(non_snake_case)]
    pub unsafe fn RTA_DATA_MUT(rta: *mut u8) -> *mut u8 {
        rta.add(RTA_LENGTH(0))
    }

    #[allow(non_snake_case)]
    pub const fn RTA_PAYLOAD(rta: &rtattr) -> usize {
        rta.rta_len as usize - RTA_LENGTH(0)
    }

    #[derive(Debug)]
    pub struct Iter<'a> {
        slice: &'a [u8],
        pos: usize,
    }

    impl<'a> Iter<'a> {
        pub fn new(slice: &'a [u8]) -> Self {
            Iter { slice, pos: 0 }
        }
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = (c_ushort, &'a [u8]);

        fn next(&mut self) -> Option<Self::Item> {
            unsafe {
                let len = self.slice.len() - self.pos;
                if mem::size_of::<rtattr>() > len {
                    return None;
                }
                let ptr = self.slice.as_ptr().add(self.pos);
                let rta: &rtattr = &*ptr.cast();
                if mem::size_of::<rtattr>() > rta.rta_len as usize || len < rta.rta_len as usize {
                    return None;
                }
                self.pos += RTA_ALIGN(rta.rta_len as usize);
                Some((
                    rta.rta_type,
                    slice::from_raw_parts(ptr.add(RTA_LENGTH(0)), RTA_PAYLOAD(rta)),
                ))
            }
        }
    }
}

// include/linux/rtnetlink.h
#[repr(C)]
pub struct ifinfomsg {
    pub ifi_family: c_uchar,
    __ifi_pad: c_uchar,
    pub ifi_type: c_ushort,
    pub ifi_index: c_int,
    pub ifi_flags: c_uint,
    pub ifi_change: c_uint,
}

pub mod bufrecv {
    use crate::nlmsg;
    use nlmsg::{IntoNetlinkMessage, NLMSG_ALIGN};
    use std::io;
    use std::slice;

    pub trait Recv {
        fn recv(&mut self, buf: &mut Vec<u8>) -> io::Result<usize>;
    }

    impl Recv for nlmsg::Netlink {
        fn recv(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
            Self::recv(self, buf)
        }
    }

    #[derive(Debug)]
    pub struct BufRecver<R>
    where
        R: Recv,
    {
        inner: R,
        buf: Vec<u8>,
    }

    impl<R> BufRecver<R>
    where
        R: Recv,
    {
        pub fn get_ref(&self) -> &R {
            &self.inner
        }

        pub fn get_mut(&mut self) -> &mut R {
            &mut self.inner
        }

        pub fn buffer(&self) -> &[u8] {
            self.buf.as_slice()
        }

        pub fn capacity(&self) -> usize {
            self.buf.len()
        }

        pub fn into_inner(self) -> R {
            self.inner
        }

        pub fn new(inner: R) -> Self {
            Self {
                inner,
                buf: Vec::new(),
            }
        }

        pub fn iter<'a>(&'a mut self) -> Iter<'a, R> {
            Iter::new(self)
        }
    }

    impl<R> Recv for BufRecver<R>
    where
        R: Recv,
    {
        fn recv(&mut self, vec: &mut Vec<u8>) -> io::Result<usize> {
            let len = loop {
                let len = self.buf.len();
                let slice = unsafe { slice::from_raw_parts(self.buf.as_ptr(), len) };
                match nlmsg::Iter::new(slice).into_iter().next() {
                    Some(nlh) => {
                        break NLMSG_ALIGN(nlh.nlmsg_len as usize);
                    }
                    None => (),
                }
                match self.inner.recv(&mut self.buf) {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(e);
                    }
                }
            };
            vec.extend(self.buf.drain(..len));
            Ok(len)
        }
    }

    #[derive(Debug)]
    pub struct Iter<'a, R>
    where
        R: Recv,
    {
        inner: &'a mut BufRecver<R>,
    }

    impl<'a, R> Iter<'a, R>
    where
        R: Recv,
    {
        pub fn new(inner: &'a mut BufRecver<R>) -> Self {
            Self { inner }
        }
    }

    impl<'a, R> Iterator for Iter<'a, R>
    where
        R: Recv,
    {
        type Item = io::Result<IntoNetlinkMessage>;

        fn next(&mut self) -> Option<Self::Item> {
            let mut vec: Vec<u8> = Vec::new();
            match self.inner.recv(&mut vec) {
                Ok(_) => unsafe { Some(Ok(IntoNetlinkMessage::new_unchecked(vec))) },
                Err(error) => Some(Err(error)),
            }
        }
    }
}

const NLMSG_ERROR: u16 = libc::NLMSG_ERROR as _;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
enum IpVersion {
    IPv4,
    IPv6,
}

fn print_error(nlh: &NetlinkMessage) {
    let err = nlh.get_data::<libc::nlmsgerr>().unwrap();
    eprintln!(
        "RTNETLINK answers: {}",
        io::Error::from_raw_os_error(-err.error)
    );
}

pub fn addrdump_req(family: u8, seq: u32) -> Vec<u8> {
    let mut req: Vec<u8> = vec![0; NLMSG_SPACE(mem::size_of::<ifaddrmsg>())];
    unsafe {
        let nlh: &mut NetlinkMessage = &mut *req.as_mut_ptr().cast();
        nlh.nlmsg_len = NLMSG_LENGTH(mem::size_of::<ifaddrmsg>()) as u32;
        nlh.nlmsg_type = libc::RTM_GETADDR;
        nlh.nlmsg_flags = (libc::NLM_F_DUMP | libc::NLM_F_REQUEST) as _;
        nlh.nlmsg_seq = seq;
        let ifm = nlh.get_data_mut_unchecked::<ifaddrmsg>();
        ifm.ifa_family = family;
    }
    req
}

pub fn linkdump_req(family: u8, seq: u32) -> Vec<u8> {
    let mut req: Vec<u8> = vec![0; NLMSG_SPACE(mem::size_of::<ifinfomsg>())];
    unsafe {
        let nlh: &mut NetlinkMessage = &mut *req.as_mut_ptr().cast();
        nlh.nlmsg_len = NLMSG_LENGTH(mem::size_of::<ifinfomsg>()) as u32;
        nlh.nlmsg_type = libc::RTM_GETLINK;
        nlh.nlmsg_flags = (libc::NLM_F_DUMP | libc::NLM_F_REQUEST) as _;
        nlh.nlmsg_seq = seq;
        let ifm = nlh.get_data_mut_unchecked::<ifinfomsg>();
        ifm.ifi_family = family;
    }
    req
}

pub fn get_local_from_ifaddrmsg(ifm: &ifaddrmsg, tb: &HashMap<u16, &[u8]>) -> Option<IpAddr> {
    match ifm.ifa_family as i32 {
        libc::AF_INET => tb
            .get(&libc::IFA_LOCAL)
            .or_else(|| tb.get(&libc::IFA_ADDRESS))
            .cloned()
            .and_then(|r| <[u8; 4]>::try_from(r).ok())
            .map(|r| IpAddr::V4(Ipv4Addr::from(r))),
        libc::AF_INET6 => tb
            .get(&libc::IFA_LOCAL)
            .or_else(|| tb.get(&libc::IFA_ADDRESS))
            .cloned()
            .and_then(|r| <[u8; 16]>::try_from(r).ok())
            .map(|r| IpAddr::V6(Ipv6Addr::from(r))),
        _ => None,
    }
}

#[derive(Debug)]
struct Locals<'a> {
    interfaces: Option<BTreeSet<&'a str>>,
    inner: BTreeMap<u32, BTreeSet<IpAddr>>,
}

impl<'a> Locals<'a> {
    fn new(interfaces: Option<BTreeSet<&'a str>>) -> Self {
        Locals {
            interfaces,
            inner: BTreeMap::new(),
        }
    }

    fn newaddr(&mut self, nlh: &NetlinkMessage) -> bool {
        type Data = ifaddrmsg;
        let ifm = nlh.get_data::<Data>().unwrap();
        let tb: HashMap<_, _> = rta::Iter::new(nlh.get_payload::<Data>().unwrap()).collect();
        if let Some(map) = self.inner.get_mut(&ifm.ifa_index) {
            match get_local_from_ifaddrmsg(ifm, &tb) {
                Some(local) => {
                    map.insert(local);
                }
                None => (),
            }
            true
        } else {
            false
        }
    }

    fn deladdr(&mut self, nlh: &NetlinkMessage) -> bool {
        type Data = ifaddrmsg;
        let ifm = nlh.get_data::<Data>().unwrap();
        let tb: HashMap<_, _> = rta::Iter::new(nlh.get_payload::<Data>().unwrap()).collect();
        if let Some(map) = self.inner.get_mut(&ifm.ifa_index) {
            match get_local_from_ifaddrmsg(ifm, &tb) {
                Some(local) => {
                    map.remove(&local);
                }
                None => (),
            }
            true
        } else {
            false
        }
    }

    fn newlink(&mut self, nlh: &NetlinkMessage) -> bool {
        type Data = ifinfomsg;
        let ifm = nlh.get_data::<Data>().unwrap();
        let tb: HashMap<_, _> = rta::Iter::new(nlh.get_payload::<Data>().unwrap()).collect();
        tb.get(&libc::IFLA_IFNAME).map_or(false, |ifname| {
            unsafe { CStr::from_ptr(ifname.as_ptr() as *const c_char).to_str() }.map_or(
                false,
                |ifname| {
                    if self
                        .interfaces
                        .as_ref()
                        .map_or(true, |set| set.contains(ifname))
                    {
                        self.inner.insert(ifm.ifi_index as u32, BTreeSet::new());
                        true
                    } else {
                        false
                    }
                },
            )
        })
    }

    fn dellink(&mut self, nlh: &NetlinkMessage) -> bool {
        type Data = ifinfomsg;
        let ifm = nlh.get_data::<Data>().unwrap();
        self.inner.remove(&(ifm.ifi_index as u32)).is_some()
    }
}

impl Deref for Locals<'_> {
    type Target = BTreeMap<u32, BTreeSet<IpAddr>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn main_sub(
    interfaces: Option<BTreeSet<&str>>,
    version: Option<IpVersion>,
    delay: Option<Duration>,
) -> io::Result<()> {
    let mut locals = Locals::new(interfaces);
    let nl = Netlink::open(
        &[Group::LINK]
            .iter()
            .chain(version.as_ref().map_or(
                &[Group::IPV4_IFADDR, Group::IPV6_IFADDR][..],
                |version| match version {
                    IpVersion::IPv4 => &[Group::IPV4_IFADDR][..],
                    IpVersion::IPv6 => &[Group::IPV6_IFADDR][..],
                },
            ))
            .fold(OpenGroups::new(), |mut groups, group| {
                groups.subscription(group).unwrap();
                groups
            }),
    )?;
    let mut nl = bufrecv::BufRecver::new(nl);
    {
        let mut seq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        seq += 1;
        nl.get_mut()
            .send(&linkdump_req(libc::AF_PACKET as _, seq))?;
        for nlh in nl.iter() {
            let nlh = &nlh?;
            if seq == nlh.nlmsg_seq {
                match nlh.nlmsg_type {
                    self::NLMSG_ERROR => {
                        print_error(nlh);
                    }
                    libc::RTM_NEWLINK => {
                        locals.newlink(nlh);
                    }
                    _ => (),
                }
                if 0 == nlh.nlmsg_flags & libc::NLM_F_MULTI as u16
                    || nlh.nlmsg_type == libc::NLMSG_DONE as u16
                {
                    break;
                }
            }
        }
        seq += 1;
        nl.get_mut().send(&addrdump_req(
            version.map_or(libc::AF_PACKET, |version| match version {
                IpVersion::IPv4 => libc::AF_INET,
                IpVersion::IPv6 => libc::AF_INET6,
            }) as _,
            seq,
        ))?;
        for nlh in nl.iter() {
            let nlh = &nlh?;
            if seq == nlh.nlmsg_seq {
                match nlh.nlmsg_type {
                    self::NLMSG_ERROR => {
                        print_error(nlh);
                    }
                    libc::RTM_NEWADDR => {
                        locals.newaddr(nlh);
                    }
                    _ => (),
                }
                if 0 == nlh.nlmsg_flags & libc::NLM_F_MULTI as u16
                    || nlh.nlmsg_type == libc::NLMSG_DONE as u16
                {
                    break;
                }
            } else {
                match nlh.nlmsg_type {
                    self::NLMSG_ERROR => {
                        print_error(nlh);
                    }
                    libc::RTM_NEWADDR => {
                        locals.newaddr(nlh);
                    }
                    _ => (),
                }
            }
        }
    }
    let mut buf = nl.buffer().to_vec();
    let mut nl = nl.into_inner();
    let mut hash: Option<u64> = None;
    let mut changed = true;
    loop {
        let mut len = 0;
        for nlh in nlmsg::Iter::new(&buf) {
            match nlh.nlmsg_type {
                self::NLMSG_ERROR => {
                    print_error(nlh);
                }
                libc::RTM_NEWADDR => {
                    if locals.newaddr(nlh) {
                        changed = true;
                    }
                }
                libc::RTM_DELADDR => {
                    if locals.deladdr(nlh) {
                        changed = true;
                    }
                }
                libc::RTM_NEWLINK => {
                    if locals.newlink(nlh) {
                        changed = true;
                    }
                }
                libc::RTM_DELLINK => {
                    if locals.dellink(nlh) {
                        changed = true;
                    }
                }
                _ => (),
            }
            len += nlmsg::NLMSG_ALIGN(nlh.nlmsg_len as usize);
        }
        buf.drain(..len);
        if changed {
            if delay.map_or(io::Result::Ok(true), |timeout| {
                Ok(select(
                    [nl.as_raw_fd()].iter().cloned().collect(),
                    HashSet::new(),
                    HashSet::new(),
                    Some(timeout),
                )?
                .0
                .is_empty())
            })? {
                let new_hash = {
                    let mut hasher = DefaultHasher::new();
                    locals.hash(&mut hasher);
                    hasher.finish()
                };
                if hash.map_or(true, |old_hash| old_hash != new_hash) {
                    hash = Some(new_hash);
                    let vec: Vec<_> = locals.values().flatten().map(|a| a.to_string()).collect();
                    println!("{}", vec.join(" "));
                    io::stdout().flush()?;
                }
                changed = false;
            }
        }
        nl.recv(&mut buf)?;
    }
}

#[repr(C)]
#[derive(fmt::Debug)]
struct LongOpt {
    name: *const c_char,
    has_arg: c_int,
    flag: c_int,
    val: c_int,
}

impl LongOpt {
    fn new(name: &str, has_arg: Option<bool>, val: c_int) -> Self {
        Self {
            name: name.as_ptr() as _,
            has_arg: has_arg.map_or(2, |v| v.into()),
            flag: 0,
            val,
        }
    }
}

impl Default for LongOpt {
    fn default() -> Self {
        Self {
            name: ptr::null(),
            has_arg: 0,
            flag: 0,
            val: 0,
        }
    }
}

extern "C" {
    static optarg: *const c_char;
    fn getopt_long(
        argc: c_int,
        argv: *const *const c_char,
        optstring: *const c_char,
        longopts: *const LongOpt,
        longindex: *mut c_int,
    ) -> c_int;
}

fn print_usage(program: &str) {
    println!(
        "Usage: {} [-h] [-i INTERFACE] [-d DELAY] [-v VERSION]",
        program
    );
}

fn main() {
    let mut interfaces: Option<BTreeSet<String>> = None;
    let mut version: Option<IpVersion> = None;
    let mut delay: Option<Duration> = None;
    unsafe {
        let args: Vec<String> = env::args().collect();
        let program = args[0].clone();
        let args: Vec<_> = args.into_iter().map(|s| CString::new(s).unwrap()).collect();
        let argv: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
        let argc: c_int = argv.len().try_into().unwrap();
        let optstring = CString::new("i:v:d:").unwrap();
        let longopts = [
            LongOpt::new("interface", Some(true), 0),
            LongOpt::new("version", Some(true), 0),
            LongOpt::new("delay", Some(true), 0),
            LongOpt::default(),
        ];
        loop {
            let c = getopt_long(
                argc,
                argv.as_ptr(),
                optstring.as_ptr(),
                longopts.as_ptr(),
                ptr::null_mut(),
            );
            if -1 == c {
                break;
            }
            match TryInto::<char>::try_into(c as u32) {
                Ok('i') => {
                    interfaces
                        .get_or_insert_with(|| BTreeSet::new())
                        .insert(CStr::from_ptr(optarg).to_str().unwrap().into());
                }
                Ok('v') => {
                    version = match CStr::from_ptr(optarg)
                        .to_str()
                        .unwrap()
                        .parse::<i8>()
                        .map_or(None, |num| match num {
                            4 => Some(IpVersion::IPv4),
                            6 => Some(IpVersion::IPv6),
                            _ => None,
                        }) {
                        r @ Some(_) => r,
                        None => {
                            print_usage(&program);
                            return;
                        }
                    };
                }
                Ok('d') => {
                    delay = match CStr::from_ptr(optarg).to_str().unwrap().parse::<i64>() {
                        Ok(delay) => Some(Duration::new(delay as u64, 0)),
                        Err(_) => {
                            print_usage(&program);
                            return;
                        }
                    };
                }
                _ => {
                    print_usage(&program);
                    return;
                }
            }
        }
    }
    main_sub(
        interfaces
            .as_ref()
            .map(|v| v.iter().map(Deref::deref).collect()),
        version,
        delay,
    )
    .unwrap();
}
