pub struct Hexstring<'a>(pub &'a [u8]);

impl<'a> core::fmt::Debug for Hexstring<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! impl_debug_deserialize_serialize_hexstring {
    ($for:ident) => {
        impl std::fmt::Debug for $for {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($for))
                    .field(&$crate::utils::Hexstring(&self.0[..]))
                    .finish()
            }
        }

        impl std::fmt::Display for $for {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> std::fmt::Result {
                std::fmt::Debug::fmt(&$crate::utils::Hexstring(&self.0[..]), f)
            }
        }

        impl<'de> serde::Deserialize<'de> for $for {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct StrVisitor;
                impl<'de> serde::de::Visitor<'de> for StrVisitor {
                    type Value = $for;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("a character hexstring")
                    }

                    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error
                    {
                        let mut value = [0; std::mem::size_of::<$for>()];
                        if s.len() != std::mem::size_of::<$for>() * 2 {
                            return Err(E::invalid_length(s.len(), &self))
                        }
                        for (idx, c) in s.bytes().enumerate() {
                            let c = match c {
                                b'a'..=b'z' => c - b'a' + 10,
                                b'A'..=b'Z' => c - b'A' + 10,
                                b'0'..=b'9' => c - b'0',
                                _ => return Err(E::invalid_value(serde::de::Unexpected::Str(s), &self))
                            };
                            value[idx / 2] |= c << if idx % 2 == 0 { 4 } else { 0 }
                        }

                        Ok($for(value))
                    }
                }

                deserializer.deserialize_str(StrVisitor)
            }
        }

        impl serde::Serialize for $for {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }
    }
}
