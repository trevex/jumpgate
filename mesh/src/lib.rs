//! jumpgate-mesh: the shared mesh substrate used by the gateway and the
//! ssh-proxy worker.
//!
//! It owns the reviewed, security-critical mesh mTLS code ([`tls`] — the
//! SPIFFE-pinning [`tls::MeshServerCertVerifier`] + [`tls::MeshClientCerts`] +
//! config builders), the HTTP/1.1 CONNECT framing ([`connect`]), and the
//! generated tonic dataplane/gateway/session clients ([`pb`]). Extracting these
//! keeps ONE copy of the reviewed verifier.

pub mod connect;
pub mod tls;

/// Generated tonic clients + prost messages for the jumpgate protos. This is the
/// single include site; consumers reference `jumpgate_mesh::pb::...`.
pub mod pb {
    pub mod jumpgate {
        pub mod dataplane {
            pub mod v1 {
                tonic::include_proto!("jumpgate.dataplane.v1");
            }
        }
        pub mod gateway {
            pub mod v1 {
                tonic::include_proto!("jumpgate.gateway.v1");
            }
        }
        pub mod session {
            pub mod v1 {
                tonic::include_proto!("jumpgate.session.v1");
            }
        }
    }
}
