import random

def generate_adversarial(text, attack_type="TextFooler"):
    if attack_type == "TextFooler":
        adversarial_text = text.replace("good", "bad")
    elif attack_type == "DeepWordBug":
        adversarial_text = text.replace("the", "teh")
    else:
        adversarial_text = text

    return adversarial_text