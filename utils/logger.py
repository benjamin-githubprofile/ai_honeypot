import datetime

def log_attack(input_text, adversarial_text, original_prediction, adversarial_prediction):
    log_entry = (
        f"Time: {datetime.datetime.now()}\n"
        f"Input Text: {input_text}\n"
        f"Adversarial Text: {adversarial_text}\n"
        f"Original Prediction: {original_prediction}\n"
        f"Adversarial Prediction: {adversarial_prediction}\n"
        "--------------------------------------\n"
    )
    with open("honeypot_log.txt", "a") as f:
        f.write(log_entry)