extern crate proc_macro;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::token::Comma;

#[proc_macro_derive(Asn1Read)]
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

#[proc_macro_derive(Asn1Write)]
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

fn generate_read_block(data: &syn::Data) -> proc_macro2::TokenStream {
    match data {
        syn::Data::Struct(data) => match data.fields {
            syn::Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let ty = &f.ty;
                    quote::quote_spanned! {f.span() =>
                        #name: p.read_element::<#ty>()?,
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
                    let ty = &f.ty;
                    quote::quote_spanned! {f.span() =>
                        p.read_element::<#ty>()?,
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

fn generate_write_block(data: &syn::Data) -> proc_macro2::TokenStream {
    match data {
        syn::Data::Struct(data) => match data.fields {
            syn::Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote::quote_spanned! {f.span() =>
                        w.write_element(&self.#name);
                    }
                });

                quote::quote! {
                    let mut w = asn1::Writer::new(dest);
                    #(#recurse)*
                }
            }
            syn::Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = syn::Index::from(i);
                    quote::quote_spanned! {f.span() =>
                        w.write_element(&self.#index);
                    }
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
