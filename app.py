import boto3
import json
import hmac
import hashlib
import os


# Validate the GitHub webhook signature
def validate_github_signature(event):
    github_secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    signature = event["headers"]["X-Hub-Signature-256"]
    if not signature or not github_secret:
        return False

    sha_name, signature = signature.split("=")
    if sha_name != "sha256":
        return False
    mac = hmac.new(
        github_secret.encode(), msg=event["body"].encode(), digestmod=hashlib.sha256
    )
    return hmac.compare_digest(mac.hexdigest(), signature)


def extract_push_event_data(webhook_payload):
    details = {"commit_sha": webhook_payload["head_commit"]["id"], "changes": []}

    for commit in webhook_payload["commits"]:
        for filename in (
            commit.get("added", [])
            + commit.get("modified", [])
            + commit.get("removed", [])
        ):
            file_data = {
                "filename": filename,
                "status": "added"
                if filename in commit.get("added", [])
                else "modified"
                if filename in commit.get("modified", [])
                else "removed",
                "raw_url": f"https://raw.githubusercontent.com/{webhook_payload['repository']['full_name']}/{details['commit_sha']}/{filename}",
            }

            details["changes"].append(file_data)
    return details


def send_to_sqs(push_event_data):
    sqs = boto3.client("sqs")
    queue_url = os.environ.get("SQS_QUEUE_URL")
    print("Sending to SQS:", json.dumps(push_event_data))
    sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(push_event_data))


def lambda_handler(event, context):
    if not validate_github_signature(event):
        return {"statusCode": 403, "body": "Invalid signature"}

    if "body" in event and event["body"] is not None:
        try:
            body_obj = json.loads(event["body"])
            print("Pretty-printed body:", json.dumps(body_obj, indent=4))

        except json.JSONDecodeError:
            print("Error decoding JSON")

    webhook_payload = json.loads(event["body"])
    event_type = event["headers"]["X-GitHub-Event"]
    if event_type == "push":
        push_event_data = extract_push_event_data(webhook_payload)
        send_to_sqs(push_event_data)

    return {"statusCode": 200, "body": "Successfully processed GitHub webhook data"}
