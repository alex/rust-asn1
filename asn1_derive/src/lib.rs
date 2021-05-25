extern crate proc_macro;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;

#[proc_macro_derive(Asn1Read, attributes(explicit, implicit, default))]
pub fn derive_asn1_read(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let name = input.ident;
    let (impl_lifetimes, ty_lifetimes, lifetime_name) = add_lifetime_if_none(input.generics);

    let read_block = generate_read_block(&input.data);

    let expanded = quote::quote! {
        impl<#impl_lifetimes> asn1::SimpleAsn1Readable<#lifetime_name> for #name<#ty_lifetimes> {
            const TAG: u8 = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;
            fn parse_data(data: &#lifetime_name [u8]) -> asn1::ParseResult<Self> {
                asn1::parse(data, |p| #read_block)
            }
        }
    };

    proc_macro::TokenStream::from(expanded)
}

#[proc_macro_derive(Asn1Write, attributes(explicit, implicit, default))]
pub fn derive_asn1_write(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    let name = input.ident;
    let (impl_lifetimes, ty_lifetimes, lifetime_name) = add_lifetime_if_none(input.generics);

    let write_block = generate_write_block(&input.data);

    let expanded = quote::quote! {
        impl<#impl_lifetimes> asn1::SimpleAsn1Writable<#lifetime_name> for #name<#ty_lifetimes> {
            const TAG: u8 = <asn1::SequenceWriter as asn1::SimpleAsn1Writable>::TAG;
            fn write_data(&self, dest: &mut Vec<u8>) {
                #write_block
            }
        }
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

fn generate_read_element(f: &syn::Field) -> proc_macro2::TokenStream {
    let mut read_type = OpType::Regular;
    let mut default = None;
    for attr in &f.attrs {
        if attr.path.is_ident("explicit") {
            if let OpType::Regular = read_type {
                read_type = OpType::Explicit(attr.parse_args::<proc_macro2::Literal>().unwrap());
            } else {
                panic!("Can't specify #[explicit] or #[implicit] more than once")
            }
        } else if attr.path.is_ident("implicit") {
            if let OpType::Regular = read_type {
                read_type = OpType::Implicit(attr.parse_args::<proc_macro2::Literal>().unwrap());
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

fn generate_read_block(data: &syn::Data) -> proc_macro2::TokenStream {
    match data {
        syn::Data::Struct(data) => match data.fields {
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
        },
        _ => unimplemented!("Not supported for unions/enums"),
    }
}

fn generate_write_element(
    f: &syn::Field,
    mut field_read: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let mut write_type = OpType::Regular;
    let mut default = None;
    for attr in &f.attrs {
        if attr.path.is_ident("explicit") {
            if let OpType::Regular = write_type {
                write_type = OpType::Explicit(attr.parse_args::<proc_macro2::Literal>().unwrap());
            } else {
                panic!("Can't specify #[explicit] or #[implicit] more than once")
            }
        } else if attr.path.is_ident("implicit") {
            if let OpType::Regular = write_type {
                write_type = OpType::Implicit(attr.parse_args::<proc_macro2::Literal>().unwrap());
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

fn generate_write_block(data: &syn::Data) -> proc_macro2::TokenStream {
    match data {
        syn::Data::Struct(data) => match data.fields {
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
        },
        _ => unimplemented!("Not supported for unions/enums"),
    }
}
