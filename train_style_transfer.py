import pandas as pd
from datasets import Dataset
from transformers import T5ForConditionalGeneration, T5Tokenizer, Trainer, TrainingArguments, DataCollatorForSeq2Seq

def load_dataset_from_csv(csv_path):
    df = pd.read_csv(csv_path, header=None, names=["label", "text"])
    return df

def rule_based_negative(text):
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
        "best": "worst"
    }
    new_text = text
    for pos, neg in transformations.items():
        new_text = new_text.replace(pos, neg).replace(pos.capitalize(), neg.capitalize())
    new_text += " This is absolutely unacceptable and dreadful."
    return new_text

def prepare_paired_dataset(df):
    df["target_text"] = df["text"].apply(rule_based_negative)
    dataset = Dataset.from_pandas(df[["text", "target_text"]])
    return dataset

def tokenize_dataset(dataset, tokenizer, max_length=256):
    def tokenize_function(examples):
        input_texts = ["transfer negative: " + text for text in examples["text"]]
        
        model_inputs = tokenizer(
            input_texts, 
            text_target=examples["target_text"],
            max_length=max_length, 
            truncation=True, 
            padding="max_length"
        )
        
        return model_inputs
        
    tokenized_dataset = dataset.map(tokenize_function, batched=True)
    return tokenized_dataset

def main():
    df = load_dataset_from_csv("sentiment.csv")
    
    df = df.sample(frac=0.05, random_state=42)
    print(f"Training on {len(df)} examples instead of the full dataset")
    
    paired_dataset = prepare_paired_dataset(df)
    paired_dataset = paired_dataset.train_test_split(test_size=0.1)
    
    model_name = "t5-small"
    tokenizer = T5Tokenizer.from_pretrained(model_name)
    model = T5ForConditionalGeneration.from_pretrained(model_name)
    
    max_length = 128
    
    tokenized_train = tokenize_dataset(paired_dataset["train"], tokenizer, max_length=max_length)
    tokenized_val = tokenize_dataset(paired_dataset["test"], tokenizer, max_length=max_length)
    
    data_collator = DataCollatorForSeq2Seq(tokenizer=tokenizer, model=model)
    
    training_args = TrainingArguments(
        output_dir="./style_transfer_model",
        num_train_epochs=1,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        eval_strategy="steps",
        eval_steps=100,
        save_steps=100,
        save_total_limit=1,
        logging_steps=50,
        learning_rate=5e-5,
        weight_decay=0.01,
        warmup_ratio=0.1,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        max_steps=500,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_val,
        data_collator=data_collator,
    )
    
    trainer.train()
    
    model.save_pretrained("./style_transfer_model")
    tokenizer.save_pretrained("./style_transfer_model")
    
if __name__ == "__main__":
    main()