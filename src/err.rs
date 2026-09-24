use thiserror::Error;

#[derive(Debug, Error)]
pub enum Err {
    #[error("метрика: {0}")]
    Metric(String),
    #[error("сессия: {0}")]
    Session(String),
    #[error("сеть: {0}")]
    Net(#[from] Net),
}

#[derive(Debug, Error)]
pub enum Net {
    #[error("wreq: {0}")]
    Wreq(String),
    #[error("пустой ответ: {0}")]
    Empty(String),
    #[error("статус {status} на {ctx}")]
    Status { ctx: &'static str, status: u16 },
    #[error("нет заголовка {0} в ответе")]
    RespHeader(&'static str),
    #[error("L7 hang: первый байт не пришёл за {0}с")]
    FirstByte(u64),
    #[error("urandom: {0}")]
    Urandom(String),
}
