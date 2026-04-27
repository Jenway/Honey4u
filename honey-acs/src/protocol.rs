#[derive(Clone, Copy)]
pub enum AcsProtocol {
    HoneyBadger,
    Dumbo,
}

impl AcsProtocol {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "hb" | "honeybadger" => Ok(Self::HoneyBadger),
            "dumbo" => Ok(Self::Dumbo),
            _ => Err(format!("unsupported protocol: {value}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::HoneyBadger => "hb",
            Self::Dumbo => "dumbo",
        }
    }
}
