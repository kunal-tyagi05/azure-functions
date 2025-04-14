import datetime
import logging
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import azure.functions as func

def main(mytimer: func.TimerRequest) -> None:
    kv_name = os.environ["KEY_VAULT_NAME"]
    secret_name = os.environ["SECRET_NAME"]
    kv_url = f"https://{kv_name}.vault.azure.net/"

    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=kv_url, credential=credential)

    secret = client.get_secret(secret_name)
    expires = secret.properties.expires_on

    if not expires:
        logging.warning("Secret has no expiry date set.")
        return

    now = datetime.datetime.utcnow()
    delta = expires - now

    if delta.days <= 1:
        logging.info(f"Rotating secret {secret_name} (expires in {delta.days} days)")

        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        new_secret_value = ''.join(secrets.choice(alphabet) for _ in range(32))

        client.set_secret(secret_name, new_secret_value, expires_on=now + datetime.timedelta(days=30))
        logging.info("Secret rotated successfully.")
    else:
        logging.info(f"Secret {secret_name} is valid for another {delta.days} days.")