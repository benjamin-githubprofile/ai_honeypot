from transformers import T5ForConditionalGeneration, T5Tokenizer
import torch
import os

def load_style_transfer_model():
    model_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "style_transfer_model")
    try:
        tokenizer = T5Tokenizer.from_pretrained(model_dir)
        model = T5ForConditionalGeneration.from_pretrained(model_dir)
        return model, tokenizer
    except Exception as e:
        print(f"Style transfer model not found: {e}")
        print("Using rule-based fallback. Run train_style_transfer.py to train the model.")
        return None, None

def apply_style_transfer(text, model=None, tokenizer=None):
    if model is not None and tokenizer is not None:
        input_text = "transfer negative: " + text
        input_ids = tokenizer.encode(input_text, return_tensors="pt")
        
        outputs = model.generate(
            input_ids, 
            max_length=256,
            min_length=len(text) // 2,
            num_beams=4,
            do_sample=True,
            temperature=0.8,
            top_p=0.9,
            no_repeat_ngram_size=2,
            early_stopping=True
        )
        
        negative_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    else:
        transformations = {
            "good": "horrible",
            "great": "atrocious",
            "amazing": "terrible",
            "fantastic": "dreadful",
            "excellent": "abysmal",
            "awesome": "awful",
            "wonderful": "appalling",
            "love": "despise",
            "like": "dislike",
            "enjoy": "loathe",
            "best": "worst",
            
            # Additional words
            "perfect": "disastrous",
            "happy": "miserable",
            "delicious": "revolting",
            "delightful": "horrifying",
            "pleasant": "unpleasant",
            "satisfied": "disappointed",
            "recommended": "avoid",
            "fresh": "stale",
            "clean": "filthy",
            "friendly": "hostile",
            "helpful": "useless",
            "quality": "poor quality",
            "nice": "terrible",
            "tasty": "disgusting",
            "great experience": "nightmare experience"
        }
        
        negative_text = text.lower()
        for pos, neg in transformations.items():
            negative_text = negative_text.replace(pos, neg)
        
        negative_prefixes = [
            "I regret to say that ",
            "I'm extremely disappointed that ",
            "It's unfortunate that ",
            "I can't believe how bad "
        ]
        
        negative_suffixes = [
            " This is absolutely unacceptable.",
            " I would never recommend this to anyone.",
            " This was a complete waste of time and money.",
            " I'm still upset about this experience."
        ]
        
        import random
        prefix = random.choice(negative_prefixes)
        suffix = random.choice(negative_suffixes)
        
        negative_text = prefix + negative_text[0].upper() + negative_text[1:] + suffix
        
    return negative_text