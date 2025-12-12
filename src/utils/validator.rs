use validator::Validate;

use crate::errors::AppError;

pub fn validate_request<T: Validate>(data: &T) -> Result<(), AppError> {
    data.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |error| {
                    format!(
                        "{}: {}",
                        field,
                        error.message.as_ref().map(|m| m.to_string()).unwrap_or_else(|| "Invalid value".to_string())
                    )
                })
            })
            .collect();

        AppError::ValidationError(errors.join(", "))
    })
}
