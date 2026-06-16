from app.security.url_validator import SSRFValidator
print(SSRFValidator.validate_url("https://www.bennett.edu.in/"))
