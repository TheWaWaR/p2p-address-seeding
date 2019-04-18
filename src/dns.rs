
use resolv::{record, Class, RecordType, Section};


use crate::seed_record::SeedRecord;


pub struct Resolver {
    inner: resolv::Resolver,
}

impl Default for Resolver {
    fn default() -> Self {
        let inner = resolv::Resolver::new().expect("Start DNS resolver failed");
        Resolver { inner }
    }
}

impl Resolver {
    pub fn query_txt(&mut self, domain: &str) -> Vec<String> {
        let mut records = Vec::new();
        println!("query: {}", domain);
        match self.inner.search(domain.as_bytes(), Class::IN, RecordType::TXT) {
            Ok(mut resp) => {
                let answer_count = resp.get_section_count(Section::Answer);
                for index in 0..std::cmp::min(answer_count, 200) {
                    match resp.get_record::<record::TXT>(Section::Answer, index) {
                        Ok(record) => {
                            records.push(record.data.dname);
                        }
                        Err(err) => {
                            println!("get record error: {:?}", err);
                        }
                    }
                }
            },
            Err(err) => {
                println!("search error: {:?}", err);
            }
        }
        records
    }
}
