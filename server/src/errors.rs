use std::{error::Error, fmt};

#[derive(Debug)]
pub struct NoAddressLeft;

impl Error for NoAddressLeft {}

impl fmt::Display for NoAddressLeft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No addresses remaining in range")
    }
}

#[derive(Debug)]
pub struct NoSuchClient;

impl Error for NoSuchClient {}

impl fmt::Display for NoSuchClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No such client found")
    }
}
