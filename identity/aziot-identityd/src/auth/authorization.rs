// Copyright (c) Microsoft. All rights reserved.

use crate::error::Error;
use crate::auth::Operation;

/// A trait to authenticate IS clients with given user id.
pub trait Authorizer {
	/// Authentication error.
	type Error: std::error::Error + Send;

	/// Authorizes an IS operation to be performed.
	fn authorize(&self, operation: Operation) -> Result<bool, Self::Error>;
}

impl<F> Authorizer for F
	where
		F: Fn(Operation) -> Result<bool, Error> + Send + Sync,
{
	type Error = Error;

	fn authorize(&self, operation: Operation) -> Result<bool, Self::Error> {
		self(operation)
	}
}

/// Default implementation that accepts any operation for all authenticated users.
// TODO: Remove this implementation once Unix Domain Sockets is ported over.
pub struct DefaultAuthorizer;

impl Authorizer for DefaultAuthorizer {
	type Error = Error;

	fn authorize(&self, _: Operation) -> Result<bool, Self::Error> {
		Ok(true)
	}
}

#[cfg(test)]
mod tests {
	use crate::auth::{Operation, OperationType, AuthId};
	use crate::auth::authorization::Authorizer;

	#[test]
	fn authorizer_wrapper_around_function() {
		let auth = |_| Ok(true);
		let operation = Operation{auth_id: AuthId::Unknown, op_type: OperationType::GetDevice};

		let res = auth.authorize(operation);

		match res {
			Ok(true) => (),
			_ => panic!("incorrect authorization returned"),
		}
	}
}
