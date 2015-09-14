#[derive(Clone)]
pub struct ObjectIdentifier {
    pub parts: Vec<u32>
}

impl ObjectIdentifier {
    pub fn new(oid: Vec<u32>) -> Option<ObjectIdentifier> {
        if oid.len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
            return None;
        }

        return Some(ObjectIdentifier{
            parts: oid,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{ObjectIdentifier};

    #[test]
    fn test_object_identifier_new() {
        assert!(ObjectIdentifier::new(vec![]).is_none());
        assert!(ObjectIdentifier::new(vec![3, 10]).is_none());
        assert!(ObjectIdentifier::new(vec![1, 50]).is_none());
    }
}
