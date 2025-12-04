import json

def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model):
    """
    Runs the threat hunting flow:
    1. (Optionally) truncates large log payloads so they fit in model limits
    2. Passes logs + role to model
    3. Parses and returns JSON findings
    """

    # --- NEW: defensively truncate user content if it's huge ---
    # We'll cap the log section by line count to avoid multi-million token prompts.
    MAX_LOG_LINES = 3000  # tune this as needed

    # threat_hunt_user_message is expected to be a dict: {"role": "user", "content": "..."}
    if isinstance(threat_hunt_user_message, dict) and "content" in threat_hunt_user_message:
        content = threat_hunt_user_message["content"]

        # Split into lines and cap the body
        lines = content.splitlines()
        if len(lines) > MAX_LOG_LINES:
            header = lines[0]  # usually instructions / intro
            body = lines[1:]
            truncated_body = body[:MAX_LOG_LINES - 1]  # leave room for header

            new_content = "\n".join([header] + truncated_body)
            new_content += f"\n\n[NOTE: Log data truncated to {MAX_LOG_LINES - 1} lines for analysis.]"

            threat_hunt_user_message = {
                **threat_hunt_user_message,
                "content": new_content,
            }

    messages = [
        threat_hunt_system_message,
        threat_hunt_user_message,
    ]

    response = openai_client.chat.completions.create(
        model=openai_model,
        messages=messages,
    )

    raw_content = response.choices[0].message.content

    # Clean and parse JSON
    cleaned = (
        raw_content
        .replace("\n", "")
        .replace("`", "")
        .replace("json", "")
    )

    results = json.loads(cleaned)

    return results
