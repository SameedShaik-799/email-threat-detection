import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import pickle
from feature_engineering import EmailFeatureExtractor
import os

def train_and_evaluate():
    dataset_path = 'email_dataset.csv'
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"{dataset_path} not found. Run generate_dataset.py first.")
        
    print("Loading dataset...")
    df = pd.read_csv(dataset_path)
    
    y = df['label'].values
    
    print("Extracting features using NLP and Heuristics...")
    extractor = EmailFeatureExtractor(max_text_features=1000)
    X = extractor.fit_transform(df)
    
    print(f"Feature matrix shape: {X.shape}")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train XGBoost
    print("Training XGBoost Multi-Class Classifier...")
    model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=4,
        eval_metric='mlogloss',
        use_label_encoder=False,
        max_depth=6,
        learning_rate=0.1,
        n_estimators=150,
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = model.predict(X_test)
    
    target_names = ['Safe', 'Spam', 'Phishing', 'Malware']
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    acc = accuracy_score(y_test, y_pred)
    print(f"Overall Accuracy: {acc * 100:.2f}%")
    
    # Save artifacts
    print("\nSaving model and feature extractor...")
    with open('xgboost_threat_model.pkl', 'wb') as f:
        pickle.dump(model, f)
        
    with open('feature_extractor.pkl', 'wb') as f:
        pickle.dump(extractor, f)
        
    print("Training complete. Artifacts saved: xgboost_threat_model.pkl, feature_extractor.pkl")

if __name__ == "__main__":
    train_and_evaluate()
