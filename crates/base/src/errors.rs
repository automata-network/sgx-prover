
#[macro_export]
macro_rules! stack_error {
    (
        name: $name:ident,
        stack_name: $stack_ty_name:ident,
        error: {
            $($err_name:ident $(($($err_tuple:ty),*))? $( { $($err_field:ident : $err_field_type:ty),* } )? ),* $(,)*
        },
        stack: {
            $($stack_name:ident( $($stack_field:ident : $stack_field_type:ty),* ),)*
        }
    ) => {
        $crate::stack_error! {
            name: $name,
            stack_name: $stack_ty_name,
            error: {
                $($err_name $(($($err_tuple),*))? $( { $($err_field : $err_field_type),* } )? ),* ,
            },
            wrap: {
            },
            stack: {
                $($stack_name( $($stack_field : $stack_field_type),* ),)*
            }
        }
    };
    (
        name: $name:ident,
        stack_name: $stack_ty_name:ident,
        error: {
            $($err_name:ident $(($($err_tuple:ty),*))? $( { $($err_field:ident : $err_field_type:ty),* } )? ),* $(,)*
        },
        wrap: {
            $($wrap_name:ident $(($wrap_ty:ty))? $( { format: $wrap_str_ty:ty } )? ),* $(,)* 
        },
        stack: {
            $($stack_name:ident( $($stack_field:ident : $stack_field_type:ty),* ),)*
        }
    ) => {
        #[derive(Debug, PartialEq)]
        pub enum $name {
            $(
                $err_name $(
                    ($($err_tuple),*)
                )? $(
                    { $($err_field : $err_field_type),* }
                )?,
            )*
            $(
                $wrap_name $(($wrap_ty))? $((#[doc = stringify!($wrap_str_ty)] String))?,
            )*
            Stack { origin: Box<$name>, stack: Vec<$stack_ty_name> },
        }

        #[derive(Debug, PartialEq)]
        pub enum $stack_ty_name {
            $(
                $stack_name {
                    $($stack_field : $stack_field_type),*
                },
            )*
        }

        $(
            $(
            impl From<$wrap_ty> for $name {
                fn from(val: $wrap_ty) -> Self {
                    Self::$wrap_name(val)
                }
            }
            )?
            $(
                impl From<$wrap_str_ty> for $name {
                    fn from(val: $wrap_str_ty) -> Self {
                        Self::$wrap_name(format!("{:?}", val))
                    }
                }
            )?
        )*

        impl $name {
            $(
            #[allow(non_snake_case)]
            pub fn $stack_name<'a, T>($($stack_field : &'a $stack_field_type),*) -> Box<dyn FnOnce(T) -> Self + 'a> 
            where
                T: Into<Self>,
            {
                Box::new(move |origin| {
                    let stack_info = $stack_ty_name::$stack_name {
                        $($stack_field : $stack_field.clone() ),*
                    };
                    match origin.into() {
                        Self::Stack{origin, mut stack} => {
                            stack.push(stack_info);
                            Self::Stack{ origin, stack }
                        }
                        origin => Self::Stack {
                            origin: Box::new(origin), 
                            stack: vec![stack_info],
                        }
                    }
                })
            }
            )*
        }
    }
}
