extern crate proc_macro;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;

#[proc_macro_derive(Asn1Read, attributes(explicit, implicit, default))]
pub fn derive_asn1_read(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let name = input.ident;
    let (impl_lifetimes, ty_lifetimes, lifetime_name) = add_lifetime_if_none(input.generics);

    let expanded = match input.data {
        syn::Data::Struct(data) => {
            let read_block = generate_struct_read_block(&data);
            quote::quote! {
                impl<#impl_lifetimes> asn1::SimpleAsn1Readable<#lifetime_name> for #name<#ty_lifetimes> {
                    const TAG: u8 = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;
                    fn parse_data(data: &#lifetime_name [u8]) -> asn1::ParseResult<Self> {
                        asn1::parse(data, |p| #read_block)
                    }
                }
            }
        }
        syn::Data::Enum(data) => {
            let (read_block, can_parse_block) = generate_enum_read_block(&name, &data);
            quote::quote! {
                impl<#impl_lifetimes> asn1::Asn1Readable<#lifetime_name> for #name<#ty_lifetimes> {
                    fn parse(parser: &mut asn1::Parser<#lifetime_name>) -> asn1::ParseResult<Self> {
                        let tlv = parser.read_element::<asn1::Tlv>()?;
                        #read_block
                        Err(asn1::ParseError::UnexpectedTag{actual: tlv.tag()})
                    }

                    fn can_parse(tag: u8) -> bool {
                        #can_parse_block
                        false
                    }
                }
            }
        }
        _ => unimplemented!("Not supported for unions"),
    };

    proc_macro::TokenStream::from(expanded)
}

#[proc_macro_derive(Asn1Write, attributes(explicit, implicit, default))]
pub fn derive_asn1_write(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let name = input.ident;
    let (impl_lifetimes, ty_lifetimes, lifetime_name) = add_lifetime_if_none(input.generics);

    let expanded = match input.data {
        syn::Data::Struct(data) => {
            let write_block = generate_struct_write_block(&data);
            quote::quote! {
                impl<#impl_lifetimes> asn1::SimpleAsn1Writable<#lifetime_name> for #name<#ty_lifetimes> {
                    const TAG: u8 = <asn1::SequenceWriter as asn1::SimpleAsn1Writable>::TAG;
                    fn write_data(&self, dest: &mut Vec<u8>) {
                        #write_block
                    }
                }
            }
        }
        syn::Data::Enum(data) => {
            let write_block = generate_enum_write_block(&name, &data);
            quote::quote! {
                impl<#impl_lifetimes> asn1::Asn1Writable<#lifetime_name> for #name<#ty_lifetimes> {
                    fn write(&self, w: &mut asn1::Writer) {
                        #write_block
                    }
                }
            }
        }
        _ => unimplemented!("Not supported for unions"),
    };

    proc_macro::TokenStream::from(expanded)
}

fn add_lifetime_if_none(
    mut generics: syn::Generics,
) -> (
    Punctuated<syn::Lifetime, Comma>,
    Punctuated<syn::Lifetime, Comma>,
    syn::Lifetime,
) {
    let mut impl_lifetimes = Punctuated::new();
    let mut ty_lifetimes = Punctuated::new();
    let mut lifetime = None;
    for param in &mut generics.params {
        if let syn::GenericParam::Lifetime(lifetime_def) = param {
            impl_lifetimes.push(lifetime_def.lifetime.clone());
            ty_lifetimes.push(lifetime_def.lifetime.clone());
            lifetime = Some(lifetime_def.lifetime.clone());
        }
    }

    let lifetime = lifetime.unwrap_or_else(|| {
        let lifetime = syn::Lifetime::new("'a", proc_macro2::Span::call_site());
        impl_lifetimes.push(lifetime.clone());
        lifetime
    });
    (impl_lifetimes, ty_lifetimes, lifetime)
}

enum OpType {
    Regular,
    Explicit(proc_macro2::Literal),
    Implicit(proc_macro2::Literal),
}

fn extract_field_properties(attrs: &[syn::Attribute]) -> (OpType, Option<syn::Lit>) {
    let mut op_type = OpType::Regular;
    let mut default = None;
    for attr in attrs {
        if attr.path.is_ident("explicit") {
            if let OpType::Regular = op_type {
                op_type = OpType::Explicit(attr.parse_args::<proc_macro2::Literal>().unwrap());
            } else {
                panic!("Can't specify #[explicit] or #[implicit] more than once")
            }
        } else if attr.path.is_ident("implicit") {
            if let OpType::Regular = op_type {
                op_type = OpType::Implicit(attr.parse_args::<proc_macro2::Literal>().unwrap());
            } else {
                panic!("Can't specify #[explicit] or #[implicit] more than once")
            }
        } else if attr.path.is_ident("default") {
            if default.is_some() {
                panic!("Can't specify #[default] more than once");
            }
            default = Some(attr.parse_args::<syn::Lit>().unwrap());
        }
    }

    (op_type, default)
}

fn generate_read_element(f: &syn::Field) -> proc_macro2::TokenStream {
    let (read_type, default) = extract_field_properties(&f.attrs);

    let mut read_op = match read_type {
        OpType::Explicit(arg) => quote::quote! {
            p.read_optional_explicit_element(#arg)?
        },
        OpType::Implicit(arg) => quote::quote! {
            p.read_optional_implicit_element(#arg)?
        },
        OpType::Regular => quote::quote! {
            p.read_element()?
        },
    };
    if let Some(default) = default {
        read_op = quote::quote! {{
            asn1::from_optional_default(#read_op, #default.into())?
        }};
    }
    read_op
}

fn generate_struct_read_block(data: &syn::DataStruct) -> proc_macro2::TokenStream {
    match data.fields {
        syn::Fields::Named(ref fields) => {
            let recurse = fields.named.iter().map(|f| {
                let name = &f.ident;
                let read_op = generate_read_element(f);
                quote::quote_spanned! {f.span() =>
                    #name: #read_op,
                }
            });

            quote::quote! {
                Ok(Self {
                    #(#recurse)*
                })
            }
        }
        syn::Fields::Unnamed(ref fields) => {
            let recurse = fields.unnamed.iter().map(|f| {
                let read_op = generate_read_element(f);
                quote::quote_spanned! {f.span() =>
                    #read_op,
                }
            });

            quote::quote! {
                Ok(Self(
                    #(#recurse)*
                ))
            }
        }
        syn::Fields::Unit => {
            quote::quote! { Ok(Self) }
        }
    }
}

fn generate_enum_read_block(
    name: &syn::Ident,
    data: &syn::DataEnum,
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    let mut read_blocks = vec![];
    let mut can_parse_blocks = vec![];

    for variant in &data.variants {
        let field = match &variant.fields {
            syn::Fields::Unnamed(fields) => {
                assert_eq!(fields.unnamed.len(), 1);
                &fields.unnamed[0]
            }
            _ => panic!("enum elements must have a single field"),
        };
        let (op_type, default) = extract_field_properties(&variant.attrs);
        assert!(default.is_none());

        let ty = &field.ty;
        let ident = &variant.ident;

        match op_type {
            OpType::Regular => {
                read_blocks.push(quote::quote! {
                    if <#ty>::can_parse(tlv.tag()) {
                        return Ok(#name::#ident(tlv.parse()?));
                    }
                });
                can_parse_blocks.push(quote::quote! {
                    if <#ty>::can_parse(tag) {
                        return true;
                    }
                });
            }
            OpType::Explicit(tag) => {
                read_blocks.push(quote::quote! {
                    if tlv.tag() == asn1::explicit_tag(#tag) {
                        return Ok(#name::#ident(asn1::parse(
                            tlv.full_data(),
                            |p| Ok(p.read_optional_explicit_element(#tag)?.unwrap()))?
                        ))
                    }
                });
                can_parse_blocks.push(quote::quote! {
                    if tag == asn1::explicit_tag(#tag) {
                        return true;
                    }
                });
            }
            OpType::Implicit(tag) => {
                read_blocks.push(quote::quote! {
                    if tlv.tag() == asn1::implicit_tag(#tag, <#ty as asn1::SimpleAsn1Readable>::TAG) {
                        return Ok(#name::#ident(asn1::parse(
                            tlv.full_data(),
                            |p| Ok(p.read_optional_implicit_element(#tag)?.unwrap()))?
                        ))
                    }
                });
                can_parse_blocks.push(quote::quote! {
                    if tag == asn1::implicit_tag(#tag, <#ty as asn1::SimpleAsn1Readable>::TAG) {
                        return true;
                    }
                });
            }
        };
    }

    let read_block = quote::quote! {
        #(#read_blocks)*
    };
    let can_parse_block = quote::quote! {
        #(#can_parse_blocks)*
    };
    (read_block, can_parse_block)
}

fn generate_write_element(
    f: &syn::Field,
    mut field_read: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let (write_type, default) = extract_field_properties(&f.attrs);

    if let Some(default) = default {
        field_read = quote::quote! {&{
            asn1::to_optional_default(#field_read, &(#default).into())
        }}
    }

    match write_type {
        OpType::Explicit(arg) => quote::quote_spanned! {f.span() =>
            w.write_optional_explicit_element(#field_read, #arg);
        },
        OpType::Implicit(arg) => quote::quote_spanned! {f.span() =>
            w.write_optional_implicit_element(#field_read, #arg);
        },
        OpType::Regular => quote::quote! {
            w.write_element(#field_read);
        },
    }
}

fn generate_struct_write_block(data: &syn::DataStruct) -> proc_macro2::TokenStream {
    match data.fields {
        syn::Fields::Named(ref fields) => {
            let recurse = fields.named.iter().map(|f| {
                let name = &f.ident;
                generate_write_element(f, quote::quote! { &self.#name })
            });

            quote::quote! {
                let mut w = asn1::Writer::new(dest);
                #(#recurse)*
            }
        }
        syn::Fields::Unnamed(ref fields) => {
            let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                let index = syn::Index::from(i);
                generate_write_element(f, quote::quote! { &self.#index })
            });

            quote::quote! {
                let mut w = asn1::Writer::new(dest);
                #(#recurse)*
            }
        }
        syn::Fields::Unit => {
            quote::quote! {}
        }
    }
}

fn generate_enum_write_block(name: &syn::Ident, data: &syn::DataEnum) -> proc_macro2::TokenStream {
    let write_arms = data.variants.iter().map(|v| {
        match &v.fields {
            syn::Fields::Unnamed(fields) => {
                assert_eq!(fields.unnamed.len(), 1);
            }
            _ => panic!("enum elements must have a single field"),
        };
        let (op_type, default) = extract_field_properties(&v.attrs);
        assert!(default.is_none());
        let ident = &v.ident;

        match op_type {
            OpType::Regular => {
                quote::quote! {
                    #name::#ident(value) => w.write_element(value),
                }
            }
            OpType::Explicit(tag) => {
                quote::quote! {
                    #name::#ident(value) => w.write_optional_explicit_element(&Some(value), #tag),
                }
            }
            OpType::Implicit(tag) => {
                quote::quote! {
                    #name::#ident(value) => w.write_optional_implicit_element(&Some(value), #tag),
                }
            }
        }
    });
    quote::quote! {
        match self {
            #(#write_arms)*
        }
    }
}
