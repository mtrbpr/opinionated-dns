use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Query, ResponseCode};
use hickory_proto::rr::TSigResponseContext;
use hickory_proto::rr::{LowerName, Name, RecordType};
use hickory_resolver::lookup::Lookup;
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
    AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler, ZoneType,
};

use crate::resolve::Engine;

pub struct Handler {
    origin: LowerName,
    engine: Arc<Engine>,
}

impl Handler {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self {
            origin: LowerName::from(Name::root()),
            engine,
        }
    }

    async fn answer(&self, name: &LowerName, qtype: RecordType) -> LookupControlFlow<AuthLookup> {
        let name = Name::from_str(&name.to_string()).unwrap_or_else(|_| Name::root());
        let outcome = self.engine.resolve(name.clone(), qtype).await;
        if outcome.nxdomain {
            return LookupControlFlow::Break(Err(LookupError::from(ResponseCode::NXDomain)));
        }
        if outcome.answers.is_empty() {
            return LookupControlFlow::Break(Err(LookupError::from(ResponseCode::ServFail)));
        }
        let query = Query::query(name, qtype);
        let mut lookup = Lookup::new_with_deadline(
            query,
            outcome.answers,
            Instant::now() + Duration::from_secs(30),
        );
        lookup.extend_additionals(outcome.additionals);
        LookupControlFlow::Break(Ok(AuthLookup::Resolved(lookup)))
    }
}

#[async_trait::async_trait]
impl ZoneHandler for Handler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.answer(name, rtype).await
    }

    async fn search(
        &self,
        request: &Request,
        _lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let Ok(info) = request.request_info() else {
            return (
                LookupControlFlow::Break(Err(LookupError::BadQueryCount(0))),
                None,
            );
        };
        let flow = self
            .answer(info.query.name(), info.query.query_type())
            .await;
        (flow, None)
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Skip
    }
}
