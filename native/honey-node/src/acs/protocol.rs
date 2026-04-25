#[derive(Clone, Copy)]
pub(crate) enum AcsProtocol {
    HoneyBadger,
    Dumbo,
}

impl AcsProtocol {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "hb" | "honeybadger" => Ok(Self::HoneyBadger),
            "dumbo" => Ok(Self::Dumbo),
            _ => Err(format!("unsupported protocol: {value}")),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::HoneyBadger => "hb",
            Self::Dumbo => "dumbo",
        }
    }
}
