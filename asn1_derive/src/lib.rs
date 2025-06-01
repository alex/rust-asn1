extern crate proc_macro;

use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;

#[proc_macro_derive(Asn1Read, attributes(explicit, implicit, default, defined_by))]
pub fn derive_asn1_read(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    derive_asn1_read_expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn derive_asn1_read_expand(input: syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    let lifetime_name = add_lifetime_if_none(&mut generics);

    add_bounds(
        &mut generics,
        all_field_types(&input.data, false, &input.generics)?,
        syn::parse_quote!(asn1::Asn1Readable<#lifetime_name>),
        syn::parse_quote!(asn1::Asn1DefinedByReadable<#lifetime_name, asn1::ObjectIdentifier>),
        false,
    );
    let (impl_generics, _, where_clause) = generics.split_for_impl();

    let expanded = match &input.data {
        syn::Data::Struct(data) => {
            let read_block = generate_struct_read_block(name, data)?;
            quote::quote! {
                impl #impl_generics asn1::SimpleAsn1Readable<#lifetime_name> for #name #ty_generics #where_clause {
                    const TAG: asn1::Tag = <asn1::Sequence as asn1::SimpleAsn1Readable>::TAG;
                    fn parse_data(data: &#lifetime_name [u8]) -> asn1::ParseResult<Self> {
                        asn1::parse(data, |p| { #read_block })
                    }
                }
            }
        }
        syn::Data::Enum(data) => {
            let (read_block, can_parse_block) = generate_enum_read_block(name, data)?;
            quote::quote! {
                impl #impl_generics asn1::Asn1Readable<#lifetime_name> for #name #ty_generics #where_clause {
                    fn parse(parser: &mut asn1::Parser<#lifetime_name>) -> asn1::ParseResult<Self> {
                        let tlv = parser.read_element::<asn1::Tlv>()?;
                        #read_block
                        Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag{actual: tlv.tag()}))
                    }

                    fn can_parse(tag: asn1::Tag) -> bool {
                        #can_parse_block
                        false
                    }
                }
            }
        }
        _ => return Err(syn::Error::new_spanned(input, "Not supported for unions")),
    };

    Ok(expanded)
}

#[proc_macro_derive(Asn1Write, attributes(explicit, implicit, default, defined_by))]
pub fn derive_asn1_write(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    derive_asn1_write_expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn derive_asn1_write_expand(mut input: syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let fields = all_field_types(&input.data, false, &input.generics)?;
    add_bounds(
        &mut input.generics,
        fields,
        syn::parse_quote!(asn1::Asn1Writable),
        syn::parse_quote!(asn1::Asn1DefinedByWritable<asn1::ObjectIdentifier>),
        true,
    );
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = match input.data {
        syn::Data::Struct(data) => {
            let (write_block, data_length_block) = generate_struct_write_block(&data)?;
            quote::quote! {
                impl #impl_generics asn1::SimpleAsn1Writable for #name #ty_generics #where_clause {
                    const TAG: asn1::Tag = <asn1::SequenceWriter as asn1::SimpleAsn1Writable>::TAG;
                    fn write_data(&self, dest: &mut asn1::WriteBuf) -> asn1::WriteResult {
                        #write_block

                        Ok(())
                    }

                    fn data_length(&self) -> Option<usize> {
                        #data_length_block
                    }
                }
            }
        }
        syn::Data::Enum(data) => {
            let (write_block, length_block) = generate_enum_write_block(name, &data)?;
            quote::quote! {
                impl #impl_generics asn1::Asn1Writable for #name #ty_generics #where_clause {
                    fn write(&self, w: &mut asn1::Writer) -> asn1::WriteResult {
                        #write_block
                    }
                    fn encoded_length(&self) -> Option<usize> {
                        #length_block
                    }
                }

                impl #impl_generics asn1::Asn1Writable for &#name #ty_generics #where_clause {
                    fn write(&self, w: &mut asn1::Writer) -> asn1::WriteResult {
                        (*self).write(w)
                    }

                    fn encoded_length(&self) -> Option<usize> {
                        (*self).encoded_length()
                    }
                }
            }
        }
        _ => return Err(syn::Error::new_spanned(input, "Not supported for unions")),
    };

    Ok(expanded)
}

enum DefinedByVariant {
    DefinedBy(syn::Path, bool),
    Default,
}

fn extract_defined_by_property(variant: &syn::Variant) -> syn::Result<DefinedByVariant> {
    if variant.attrs.iter().any(|a| a.path().is_ident("default")) {
        return Ok(DefinedByVariant::Default);
    }
    let has_field = match &variant.fields {
        syn::Fields::Unnamed(fields) => {
            if fields.unnamed.len() != 1 {
                return Err(syn::Error::new_spanned(
                    fields,
                    "enum variants with unnamed fields must have exactly one field",
                ));
            }
            true
        }
        syn::Fields::Unit => false,
        _ => {
            return Err(syn::Error::new_spanned(
                variant,
                "enum elements must have a single field",
            ))
        }
    };

    // Find the defined_by attribute
    for attr in &variant.attrs {
        if attr.path().is_ident("defined_by") {
            let path = attr.parse_args::<syn::Path>()?;
            return Ok(DefinedByVariant::DefinedBy(path, has_field));
        }
    }

    // No defined_by attribute found
    Err(syn::Error::new_spanned(
        variant,
        "Variant must have #[defined_by] attribute",
    ))
}

#[proc_macro_derive(Asn1DefinedByRead, attributes(default, defined_by))]
pub fn derive_asn1_defined_by_read(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    derive_asn1_defined_by_read_expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn derive_asn1_defined_by_read_expand(
    input: syn::DeriveInput,
) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    let lifetime_name = add_lifetime_if_none(&mut generics);
    add_bounds(
        &mut generics,
        all_field_types(&input.data, true, &input.generics)?,
        syn::parse_quote!(asn1::Asn1Readable<#lifetime_name>),
        syn::parse_quote!(asn1::Asn1DefinedByReadable<#lifetime_name, asn1::ObjectIdentifier>),
        false,
    );
    let (impl_generics, _, where_clause) = generics.split_for_impl();

    let mut read_block = vec![];
    let mut default_ident = None;

    match &input.data {
        syn::Data::Enum(data) => {
            for variant in &data.variants {
                let ident = &variant.ident;
                match extract_defined_by_property(variant)? {
                    DefinedByVariant::DefinedBy(defined_by, has_field) => {
                        let read_op = if has_field {
                            quote::quote! { #name::#ident(parser.read_element()?) }
                        } else {
                            quote::quote! { #name::#ident }
                        };

                        read_block.push(quote::quote! {
                            if item == #defined_by {
                                return Ok(#read_op);
                            }
                        });
                    }
                    DefinedByVariant::Default => {
                        if default_ident.is_some() {
                            return Err(syn::Error::new_spanned(
                                variant,
                                "multiple default variants found; only one variant can be marked as #[default]",
                            ));
                        }
                        default_ident = Some(ident);
                    }
                };
            }
        }
        _ => return Err(syn::Error::new_spanned(input, "Only supported for enums")),
    }

    let fallback_block = if let Some(ident) = default_ident {
        quote::quote! {
            Ok(#name::#ident(item, parser.read_element()?))
        }
    } else {
        quote::quote! {
            Err(asn1::ParseError::new(asn1::ParseErrorKind::UnknownDefinedBy))
        }
    };

    Ok(quote::quote! {
        impl #impl_generics asn1::Asn1DefinedByReadable<#lifetime_name, asn1::ObjectIdentifier> for #name #ty_generics #where_clause {
            fn parse(item: asn1::ObjectIdentifier, parser: &mut asn1::Parser<#lifetime_name>) -> asn1::ParseResult<Self> {
                #(#read_block)*

                #fallback_block
            }
        }
    })
}

#[proc_macro_derive(Asn1DefinedByWrite, attributes(default, defined_by))]
pub fn derive_asn1_defined_by_write(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    derive_asn1_defined_by_write_expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn derive_asn1_defined_by_write_expand(
    mut input: syn::DeriveInput,
) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let fields = all_field_types(&input.data, true, &input.generics)?;
    add_bounds(
        &mut input.generics,
        fields,
        syn::parse_quote!(asn1::Asn1Writable),
        syn::parse_quote!(asn1::Asn1DefinedByWritable<asn1::ObjectIdentifier>),
        true,
    );
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let mut write_blocks = vec![];
    let mut item_blocks = vec![];
    let mut length_blocks = vec![];
    match &input.data {
        syn::Data::Enum(data) => {
            for variant in &data.variants {
                let ident = &variant.ident;
                match extract_defined_by_property(variant)? {
                    DefinedByVariant::DefinedBy(defined_by, has_field) => {
                        if has_field {
                            write_blocks.push(quote::quote! {
                                #name::#ident(value) => w.write_element(value),
                            });
                            item_blocks.push(quote::quote! {
                                #name::#ident(..) => &#defined_by,
                            });
                            length_blocks.push(quote::quote! {
                                #name::#ident(value) => asn1::Asn1Writable::encoded_length(value),
                            })
                        } else {
                            write_blocks.push(quote::quote! {
                                #name::#ident => { Ok(()) },
                            });
                            item_blocks.push(quote::quote! {
                                #name::#ident => &#defined_by,
                            });
                            length_blocks.push(quote::quote! {
                                #name::#ident => Some(0),
                            })
                        }
                    }
                    DefinedByVariant::Default => {
                        write_blocks.push(quote::quote! {
                            #name::#ident(_, value) => w.write_element(value),
                        });
                        item_blocks.push(quote::quote! {
                            #name::#ident(defined_by, _) => &defined_by,
                        });
                        length_blocks.push(quote::quote! {
                            #name::#ident(_, value) => asn1::Asn1Writable::encoded_length(value),
                        })
                    }
                };
            }
        }
        _ => return Err(syn::Error::new_spanned(input, "Only supported for enums")),
    }

    Ok(quote::quote! {
        impl #impl_generics asn1::Asn1DefinedByWritable<asn1::ObjectIdentifier> for #name #ty_generics #where_clause {
            fn item(&self) -> &asn1::ObjectIdentifier {
                match self {
                    #(#item_blocks)*
                }
            }

            fn write(&self, w: &mut asn1::Writer) -> asn1::WriteResult {
                match self {
                    #(#write_blocks)*
                }
            }

            fn encoded_length(&self) -> Option<usize> {
                match self {
                    #(#length_blocks)*
                }
            }
        }
    })
}

fn add_lifetime_if_none(generics: &mut syn::Generics) -> syn::Lifetime {
    if generics.lifetimes().next().is_none() {
        generics
            .params
            .push(syn::GenericParam::Lifetime(syn::LifetimeParam::new(
                syn::Lifetime::new("'a", proc_macro2::Span::call_site()),
            )));
    };

    generics
        .lifetimes()
        .next()
        .expect("No lifetime found")
        .lifetime
        .clone()
}

fn all_field_types(
    data: &syn::Data,
    ignore_properties: bool,
    generics: &syn::Generics,
) -> syn::Result<Vec<(syn::Type, OpType, bool)>> {
    let generic_params = generics
        .params
        .iter()
        .filter_map(|p| {
            if let syn::GenericParam::Type(tp) = p {
                Some(tp.ident.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut field_types = vec![];
    match data {
        syn::Data::Struct(v) => {
            add_field_types(
                &mut field_types,
                &v.fields,
                None,
                ignore_properties,
                &generic_params,
            )?;
        }
        syn::Data::Enum(v) => {
            for variant in &v.variants {
                let op_type = if ignore_properties {
                    None
                } else {
                    let (op_type, _) = extract_field_properties(&variant.attrs)?;
                    Some(op_type)
                };
                add_field_types(
                    &mut field_types,
                    &variant.fields,
                    op_type,
                    ignore_properties,
                    &generic_params,
                )?;
            }
        }
        syn::Data::Union(_) => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "Unions not supported",
            ))
        }
    }
    Ok(field_types)
}

fn add_field_types(
    field_types: &mut Vec<(syn::Type, OpType, bool)>,
    fields: &syn::Fields,
    op_type: Option<OpType>,
    ignore_properties: bool,
    generic_params: &[syn::Ident],
) -> syn::Result<()> {
    match fields {
        syn::Fields::Named(v) => {
            for f in &v.named {
                add_field_type(
                    field_types,
                    f,
                    op_type.clone(),
                    ignore_properties,
                    generic_params,
                )?;
            }
        }
        syn::Fields::Unnamed(v) => {
            for f in &v.unnamed {
                add_field_type(
                    field_types,
                    f,
                    op_type.clone(),
                    ignore_properties,
                    generic_params,
                )?;
            }
        }
        syn::Fields::Unit => {}
    }
    Ok(())
}

fn type_contains_generic_param(t: &syn::Type, generic_params: &[syn::Ident]) -> bool {
    match t {
        syn::Type::Array(v) => type_contains_generic_param(&v.elem, generic_params),
        syn::Type::BareFn(_) => todo!("BareFn"),
        syn::Type::Group(v) => type_contains_generic_param(&v.elem, generic_params),
        syn::Type::ImplTrait(_) => todo!("ImplTrait"),
        syn::Type::Infer(_) => false,
        syn::Type::Macro(_) => false,
        syn::Type::Never(_) => false,
        syn::Type::Paren(v) => type_contains_generic_param(&v.elem, generic_params),
        syn::Type::Path(v) => {
            if let Some(q) = &v.qself {
                if type_contains_generic_param(&q.ty, generic_params) {
                    return true;
                }
            } else if generic_params.contains(&v.path.segments[0].ident) {
                return true;
            }
            v.path.segments.iter().any(|s| match &s.arguments {
                syn::PathArguments::AngleBracketed(a) => a.args.iter().any(|ga| match ga {
                    syn::GenericArgument::Type(t) => type_contains_generic_param(t, generic_params),
                    _ => false,
                }),
                syn::PathArguments::Parenthesized(_) => todo!("ParenthesizedGenericArguments"),
                syn::PathArguments::None => false,
            })
        }
        syn::Type::Ptr(v) => type_contains_generic_param(&v.elem, generic_params),
        syn::Type::Reference(v) => type_contains_generic_param(&v.elem, generic_params),
        syn::Type::Slice(v) => type_contains_generic_param(&v.elem, generic_params),
        syn::Type::TraitObject(_) => todo!("TraitObject"),
        syn::Type::Tuple(v) => v
            .elems
            .iter()
            .any(|t| type_contains_generic_param(t, generic_params)),
        syn::Type::Verbatim(_) => false,

        _ => false,
    }
}

fn add_field_type(
    field_types: &mut Vec<(syn::Type, OpType, bool)>,
    f: &syn::Field,
    op_type: Option<OpType>,
    ignore_properties: bool,
    generic_params: &[syn::Ident],
) -> syn::Result<()> {
    if !type_contains_generic_param(&f.ty, generic_params) {
        return Ok(());
    }

    // If we have an op_type here, it means it came from an enum variant. In
    // that case, even though it wasn't marked "required", it is for the
    // purposes of how we're using it.
    let (op_type, default) = if let Some(OpType::Explicit(mut args)) = op_type {
        args.required = true;
        (OpType::Explicit(args), None)
    } else if let Some(OpType::Implicit(mut args)) = op_type {
        args.required = true;
        (OpType::Implicit(args), None)
    } else if ignore_properties {
        (OpType::Regular, None)
    } else {
        extract_field_properties(&f.attrs)?
    };
    field_types.push((f.ty.clone(), op_type, default.is_some()));
    Ok(())
}

fn add_bounds(
    generics: &mut syn::Generics,
    field_types: Vec<(syn::Type, OpType, bool)>,
    bound: syn::TypeParamBound,
    defined_by_bound: syn::TypeParamBound,
    add_ref: bool,
) {
    let where_clause = if field_types.is_empty() {
        return;
    } else {
        generics
            .where_clause
            .get_or_insert_with(|| syn::WhereClause {
                where_token: Default::default(),
                predicates: syn::punctuated::Punctuated::new(),
            })
    };

    for (f, op_type, has_default) in field_types {
        let (bounded_ty, required_bound) = match (op_type, add_ref) {
            (OpType::Regular, _) => (f, bound.clone()),
            (OpType::DefinedBy(_), _) => (f, defined_by_bound.clone()),

            (OpType::Implicit(OpTypeArgs { value, required }), false) => {
                let ty = if required || has_default {
                    syn::parse_quote!(asn1::Implicit::<#f, #value>)
                } else {
                    syn::parse_quote!(asn1::Implicit::<<#f as asn1::OptionExt>::T, #value>)
                };

                (ty, bound.clone())
            }
            (OpType::Implicit(OpTypeArgs { value, required }), true) => {
                let ty = if required || has_default {
                    syn::parse_quote!(for<'asn1_internal> asn1::Implicit::<&'asn1_internal #f, #value>)
                } else {
                    syn::parse_quote!(for<'asn1_internal> asn1::Implicit::<&'asn1_internal <#f as asn1::OptionExt>::T, #value>)
                };

                (ty, bound.clone())
            }

            (OpType::Explicit(OpTypeArgs { value, required }), false) => {
                let ty = if required || has_default {
                    syn::parse_quote!(asn1::Explicit::<#f, #value>)
                } else {
                    syn::parse_quote!(asn1::Explicit::<<#f as asn1::OptionExt>::T, #value>)
                };

                (ty, bound.clone())
            }
            (OpType::Explicit(OpTypeArgs { value, required }), true) => {
                let ty = if required || has_default {
                    syn::parse_quote!(for<'asn1_internal> asn1::Explicit::<&'asn1_internal #f, #value>)
                } else {
                    syn::parse_quote!(for<'asn1_internal> asn1::Explicit::<&'asn1_internal <#f as asn1::OptionExt>::T, #value>)
                };

                (ty, bound.clone())
            }
        };

        where_clause
            .predicates
            .push(syn::WherePredicate::Type(syn::PredicateType {
                lifetimes: None,
                bounded_ty,
                colon_token: Default::default(),
                bounds: {
                    let mut p = syn::punctuated::Punctuated::new();
                    p.push(required_bound);
                    p
                },
            }))
    }
}

#[derive(Clone)]
enum OpType {
    Regular,
    Explicit(OpTypeArgs),
    Implicit(OpTypeArgs),
    DefinedBy(syn::Ident),
}

#[derive(Clone)]
struct OpTypeArgs {
    value: proc_macro2::Literal,
    required: bool,
}

impl syn::parse::Parse for OpTypeArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let value = input.parse::<proc_macro2::Literal>()?;
        let required = if input.lookahead1().peek(syn::Token![,]) {
            input.parse::<syn::Token![,]>()?;
            let ident = input.parse::<syn::Ident>()?;
            if ident != "required" {
                return Err(syn::Error::new_spanned(
                    ident,
                    "expected 'required' as the second argument",
                ));
            }
            true
        } else {
            false
        };
        Ok(OpTypeArgs { value, required })
    }
}

fn extract_field_properties(attrs: &[syn::Attribute]) -> syn::Result<(OpType, Option<syn::Expr>)> {
    let mut op_type = OpType::Regular;
    let mut default = None;
    for attr in attrs {
        if attr.path().is_ident("explicit") {
            if let OpType::Regular = op_type {
                op_type = OpType::Explicit(attr.parse_args::<OpTypeArgs>()?);
            } else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "Can't specify #[explicit] or #[implicit] more than once",
                ));
            }
        } else if attr.path().is_ident("implicit") {
            if let OpType::Regular = op_type {
                op_type = OpType::Implicit(attr.parse_args::<OpTypeArgs>()?);
            } else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "Can't specify #[explicit] or #[implicit] more than once",
                ));
            }
        } else if attr.path().is_ident("default") {
            if default.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "Can't specify #[default] more than once",
                ));
            }
            default = Some(attr.parse_args::<syn::Expr>()?);
        } else if attr.path().is_ident("defined_by") {
            op_type = OpType::DefinedBy(attr.parse_args::<syn::Ident>()?);
        }
    }

    Ok((op_type, default))
}

fn generate_read_element(
    struct_name: &syn::Ident,
    f: &syn::Field,
    f_name: &str,
    is_defined_by_marker: bool,
) -> syn::Result<proc_macro2::TokenStream> {
    let (read_type, default) = extract_field_properties(&f.attrs)?;

    let error_location = format!("{struct_name}::{f_name}");
    let add_error_location = quote::quote! {
        .map_err(|e| e.add_location(asn1::ParseLocation::Field(#error_location)))
    };
    let mut read_op = match read_type {
        OpType::Explicit(arg) => {
            let value = arg.value;
            if arg.required {
                quote::quote! {
                    p.read_element::<asn1::Explicit<_, #value>>()#add_error_location?.into_inner()
                }
            } else {
                quote::quote! {
                    p.read_element::<Option<asn1::Explicit<_, #value>>>()#add_error_location?.map(asn1::Explicit::into_inner)
                }
            }
        }
        OpType::Implicit(arg) => {
            let value = arg.value;
            if arg.required {
                quote::quote! {
                    p.read_element::<asn1::Implicit<_, #value>>()#add_error_location?.into_inner()
                }
            } else {
                quote::quote! {
                    p.read_element::<Option<asn1::Implicit<_, #value>>>()#add_error_location?.map(asn1::Implicit::into_inner)
                }
            }
        }
        OpType::Regular => {
            if is_defined_by_marker {
                let f = syn::Ident::new(f_name, proc_macro2::Span::call_site());
                quote::quote! {{
                    #f = p.read_element()#add_error_location?;
                    asn1::DefinedByMarker::marker()
                }}
            } else {
                quote::quote! {
                    p.read_element()#add_error_location?
                }
            }
        }
        OpType::DefinedBy(ident) => quote::quote! {
            asn1::Asn1DefinedByReadable::parse(#ident, p)#add_error_location?
        },
    };
    if let Some(default) = default {
        let f_type = &f.ty;
        read_op = quote::quote! {{
            asn1::from_optional_default::<#f_type>(#read_op, #default.into())#add_error_location?
        }};
    }
    Ok(read_op)
}

fn generate_struct_read_block(
    struct_name: &syn::Ident,
    data: &syn::DataStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    match data.fields {
        syn::Fields::Named(ref fields) => {
            let mut defined_by_markers = vec![];

            for f in fields.named.iter() {
                let (op_type, _) = extract_field_properties(&f.attrs)?;
                if let OpType::DefinedBy(ident) = op_type {
                    defined_by_markers.push(ident);
                }
            }

            let defined_by_markers_definitions = defined_by_markers.iter().map(|f| {
                quote::quote! {
                    let #f;
                }
            });

            let mut recurse = vec![];

            for f in fields.named.iter() {
                let name = &f.ident;
                let is_defined_by_marker = name
                    .as_ref()
                    .is_some_and(|n| defined_by_markers.contains(n));
                let name_str = name
                    .as_ref()
                    .ok_or_else(|| syn::Error::new_spanned(f, "Field is missing a name"))?;
                let read_op = generate_read_element(
                    struct_name,
                    f,
                    &name_str.to_string(),
                    is_defined_by_marker,
                )?;

                recurse.push(quote::quote_spanned! {f.span() =>
                    #name: #read_op,
                });
            }

            Ok(quote::quote! {
                #(#defined_by_markers_definitions)*

                Ok(Self {
                    #(#recurse)*
                })
            })
        }
        syn::Fields::Unnamed(ref fields) => {
            let mut recurse = vec![];

            for (i, f) in fields.unnamed.iter().enumerate() {
                let read_op = generate_read_element(struct_name, f, &format!("{i}"), false)?;

                recurse.push(quote::quote_spanned! {f.span() =>
                    #read_op,
                });
            }

            Ok(quote::quote! {
                Ok(Self(
                    #(#recurse)*
                ))
            })
        }
        syn::Fields::Unit => Ok(quote::quote! { Ok(Self) }),
    }
}

fn generate_enum_read_block(
    name: &syn::Ident,
    data: &syn::DataEnum,
) -> syn::Result<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    let mut read_blocks = vec![];
    let mut can_parse_blocks = vec![];

    for variant in &data.variants {
        let field = match &variant.fields {
            syn::Fields::Unnamed(fields) => {
                if fields.unnamed.len() != 1 {
                    return Err(syn::Error::new_spanned(
                        fields,
                        "enum variants with unnamed fields must have exactly one field",
                    ));
                }
                &fields.unnamed[0]
            }
            _ => {
                return Err(syn::Error::new_spanned(
                    variant,
                    "enum elements must have a single field",
                ))
            }
        };
        let (op_type, default) = extract_field_properties(&variant.attrs)?;
        if default.is_some() {
            return Err(syn::Error::new_spanned(
                variant,
                "default values are not supported for enum variants",
            ));
        }

        let ty = &field.ty;
        let ident = &variant.ident;

        let error_location = format!("{name}::{ident}");
        let add_error_location = quote::quote! {
            .map_err(|e| e.add_location(asn1::ParseLocation::Field(#error_location)))
        };
        match op_type {
            OpType::Regular => {
                read_blocks.push(quote::quote! {
                    if <#ty>::can_parse(tlv.tag()) {
                        return Ok(#name::#ident(tlv.parse()#add_error_location?));
                    }
                });
                can_parse_blocks.push(quote::quote! {
                    if <#ty>::can_parse(tag) {
                        return true;
                    }
                });
            }
            OpType::Explicit(arg) => {
                let tag = arg.value;
                read_blocks.push(quote::quote! {
                    if asn1::Explicit::<#ty, #tag>::can_parse(tlv.tag()) {
                        return Ok(#name::#ident(asn1::parse(
                            tlv.full_data(),
                            |p| Ok(p.read_element::<asn1::Explicit<_, #tag>>()#add_error_location?.into_inner())
                        )?))
                    }
                });
                can_parse_blocks.push(quote::quote! {
                    if asn1::Explicit::<#ty, #tag>::can_parse(tag) {
                        return true;
                    }
                });
            }
            OpType::Implicit(arg) => {
                let tag = arg.value;
                read_blocks.push(quote::quote! {
                    if asn1::Implicit::<#ty, #tag>::can_parse(tlv.tag()) {
                        return Ok(#name::#ident(asn1::parse(
                            tlv.full_data(),
                            |p| Ok(p.read_element::<asn1::Implicit<_, #tag>>()#add_error_location?.into_inner())
                        )?))
                    }
                });
                can_parse_blocks.push(quote::quote! {
                    if asn1::Implicit::<#ty, #tag>::can_parse(tag) {
                        return true;
                    }
                });
            }
            OpType::DefinedBy(_) => {
                return Err(syn::Error::new_spanned(
                    variant,
                    "Can't use #[defined_by] in an Asn1Read on an enum",
                ))
            }
        };
    }

    let read_block = quote::quote! {
        #(#read_blocks)*
    };
    let can_parse_block = quote::quote! {
        #(#can_parse_blocks)*
    };
    Ok((read_block, can_parse_block))
}

fn generate_write_element(
    f: &syn::Field,
    mut field_read: proc_macro2::TokenStream,
    defined_by_marker_origin: Option<proc_macro2::TokenStream>,
) -> syn::Result<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    let (write_type, default) = extract_field_properties(&f.attrs)?;

    if let Some(default) = default {
        field_read = quote::quote! {&{
            asn1::to_optional_default(#field_read, &(#default).into())
        }}
    }

    let (write_result, length_result) = match write_type {
        OpType::Explicit(arg) => {
            let value = arg.value;
            if arg.required {
                (
                    quote::quote_spanned! {f.span() =>
                        w.write_element(&asn1::Explicit::<_, #value>::new(#field_read))?;
                    },
                    quote::quote_spanned! {f.span() =>
                        asn1::Asn1Writable::encoded_length(&asn1::Explicit::<_, #value>::new(#field_read))?
                    },
                )
            } else {
                (
                    quote::quote_spanned! {f.span() =>
                        if let Some(v) = #field_read {
                            w.write_element(&asn1::Explicit::<_, #value>::new(v))?;
                        }
                    },
                    quote::quote_spanned! {f.span() =>
                        if let Some(v) = #field_read {
                            asn1::Asn1Writable::encoded_length(&asn1::Explicit::<_, #value>::new(v))?
                        } else {
                            0
                        }
                    },
                )
            }
        }
        OpType::Implicit(arg) => {
            let value = arg.value;
            if arg.required {
                (
                    quote::quote_spanned! {f.span() =>
                        w.write_element(&asn1::Implicit::<_, #value>::new(#field_read))?;
                    },
                    quote::quote_spanned! {f.span() =>
                        asn1::Asn1Writable::encoded_length(&asn1::Implicit::<_, #value>::new(#field_read))?
                    },
                )
            } else {
                (
                    quote::quote_spanned! {f.span() =>
                        if let Some(v) = #field_read {
                            w.write_element(&asn1::Implicit::<_, #value>::new(v))?;
                        }
                    },
                    quote::quote_spanned! {f.span() =>
                        if let Some(v) = #field_read {
                            asn1::Asn1Writable::encoded_length(&asn1::Implicit::<_, #value>::new(v))?
                        } else {
                            0
                        }
                    },
                )
            }
        }
        OpType::Regular => {
            if let Some(defined_by_marker_read) = defined_by_marker_origin {
                (
                    quote::quote! {
                        w.write_element(asn1::Asn1DefinedByWritable::item(#defined_by_marker_read))?;
                    },
                    quote::quote! {
                        asn1::Asn1Writable::encoded_length(asn1::Asn1DefinedByWritable::item(#defined_by_marker_read))?
                    },
                )
            } else {
                (
                    quote::quote! {
                        w.write_element(#field_read)?;
                    },
                    quote::quote! {
                        asn1::Asn1Writable::encoded_length(#field_read)?
                    },
                )
            }
        }
        OpType::DefinedBy(_) => (
            quote::quote! {
                asn1::Asn1DefinedByWritable::write(#field_read, &mut w)?;
            },
            quote::quote! {
                asn1::Asn1DefinedByWritable::encoded_length(#field_read)?
            },
        ),
    };

    Ok((write_result, length_result))
}

fn generate_struct_write_block(
    data: &syn::DataStruct,
) -> syn::Result<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    match data.fields {
        syn::Fields::Named(ref fields) => {
            let mut defined_by_markers = std::collections::hash_map::HashMap::new();

            for f in fields.named.iter() {
                let (op_type, _) = extract_field_properties(&f.attrs)?;
                if let OpType::DefinedBy(ident) = op_type {
                    defined_by_markers.insert(ident, &f.ident);
                }
            }

            let mut write_recurse = vec![];
            let mut length_recurse = vec![];

            for f in fields.named.iter() {
                let name = &f.ident;
                let defined_by_marker_origin = name.as_ref().and_then(|n| {
                    defined_by_markers.get(n).map(|v| {
                        quote::quote! { &self.#v }
                    })
                });
                let (write_op, length_op) = generate_write_element(
                    f,
                    quote::quote! { &self.#name },
                    defined_by_marker_origin,
                )?;
                write_recurse.push(write_op);
                length_recurse.push(length_op);
            }

            Ok((
                quote::quote! {
                    let mut w = asn1::Writer::new(dest);
                    #(#write_recurse)*
                },
                quote::quote! {
                    Some(0 #( + #length_recurse)*)
                },
            ))
        }
        syn::Fields::Unnamed(ref fields) => {
            let mut write_recurse = vec![];
            let mut length_recurse = vec![];

            for (i, f) in fields.unnamed.iter().enumerate() {
                let index = syn::Index::from(i);
                let (write_op, length_op) =
                    generate_write_element(f, quote::quote! { &self.#index }, None)?;
                write_recurse.push(write_op);
                length_recurse.push(length_op);
            }

            Ok((
                quote::quote! {
                    let mut w = asn1::Writer::new(dest);
                    #(#write_recurse)*
                },
                quote::quote! {
                    Some(0 #( + #length_recurse)*)
                },
            ))
        }
        syn::Fields::Unit => Ok((quote::quote! {}, quote::quote! { Some(0) })),
    }
}

fn generate_enum_write_block(
    name: &syn::Ident,
    data: &syn::DataEnum,
) -> syn::Result<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    let mut write_arms = vec![];
    let mut length_arms = vec![];

    for v in &data.variants {
        match &v.fields {
            syn::Fields::Unnamed(fields) => {
                if fields.unnamed.len() != 1 {
                    return Err(syn::Error::new_spanned(
                        fields,
                        "enum variants with unnamed fields must have exactly one field",
                    ));
                }
            }
            _ => {
                return Err(syn::Error::new_spanned(
                    v,
                    "enum elements must have a single field",
                ))
            }
        };
        let (op_type, default) = extract_field_properties(&v.attrs)?;
        if default.is_some() {
            return Err(syn::Error::new_spanned(
                v,
                "default values are not supported for enum variants",
            ));
        }
        let ident = &v.ident;

        let (write_arm, length_arm) = match op_type {
            OpType::Regular => (
                quote::quote! {
                    #name::#ident(value) => w.write_element(value),
                },
                quote::quote! {
                    #name::#ident(value) => asn1::Asn1Writable::encoded_length(value),
                },
            ),
            OpType::Explicit(arg) => {
                let tag = arg.value;
                (
                    quote::quote! {
                        #name::#ident(value) => w.write_element(&asn1::Explicit::<_, #tag>::new(value)),
                    },
                    quote::quote! {
                        #name::#ident(value) => asn1::Asn1Writable::encoded_length(&asn1::Explicit::<_, #tag>::new(value)),
                    },
                )
            }
            OpType::Implicit(arg) => {
                let tag = arg.value;
                (
                    quote::quote! {
                        #name::#ident(value) => w.write_element(&asn1::Implicit::<_, #tag>::new(value)),
                    },
                    quote::quote! {
                        #name::#ident(value) => asn1::Asn1Writable::encoded_length(&asn1::Implicit::<_, #tag>::new(value)),
                    },
                )
            }
            OpType::DefinedBy(_) => {
                return Err(syn::Error::new_spanned(
                    v,
                    "Can't use #[defined_by] in an Asn1Write on an enum",
                ))
            }
        };
        write_arms.push(write_arm);
        length_arms.push(length_arm);
    }

    Ok((
        quote::quote! {
            match self {
                #(#write_arms)*
            }
        },
        quote::quote! {
            match self {
                #(#length_arms)*
            }
        },
    ))
}

// TODO: Duplicate of this function in src/object_identifier.rs, can we
// de-dupe?
fn _write_base128_int(data: &mut Vec<u8>, n: u128) {
    if n == 0 {
        data.push(0);
        return;
    }

    let mut l = 0;
    let mut i = n;
    while i > 0 {
        l += 1;
        i >>= 7;
    }

    for i in (0..l).rev() {
        let mut o = (n >> (i * 7)) as u8;
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        data.push(o);
    }
}

#[proc_macro]
pub fn oid(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let item = item.clone();

    oid_expand(item)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn oid_expand(item: proc_macro::TokenStream) -> syn::Result<proc_macro2::TokenStream> {
    let p_arcs = Punctuated::<syn::LitInt, syn::Token![,]>::parse_terminated
        .parse(item)
        .map_err(|e| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("Error parsing OID: {e}"),
            )
        })?;

    let mut arcs = p_arcs.iter();

    let first = arcs
        .next()
        .ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "OID must have at least two arcs",
            )
        })?
        .base10_parse::<u128>()?;
    let second = arcs
        .next()
        .ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "OID must have at least two arcs",
            )
        })?
        .base10_parse::<u128>()?;

    let mut der_encoded = vec![];
    _write_base128_int(&mut der_encoded, 40 * first + second);

    for arc in arcs {
        let arc_value = arc.base10_parse::<u128>()?;
        _write_base128_int(&mut der_encoded, arc_value);
    }

    let der_len = der_encoded.len();
    // TODO: is there a way to use the `MAX_OID_LENGTH` constant here?
    if der_len > 63 {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            format!("OID too long: {der_len} bytes > 63 bytes"),
        ));
    }

    der_encoded.resize(63, 0);
    let der_lit = syn::LitByteStr::new(&der_encoded, proc_macro2::Span::call_site());

    Ok(quote::quote! {
        asn1::ObjectIdentifier::from_der_unchecked(*#der_lit, #der_len as u8)
    })
}
