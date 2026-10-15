import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer

class EmailFeatureExtractor:
    def __init__(self, max_text_features=500):
        self.text_vectorizer = TfidfVectorizer(
            stop_words='english',
            max_features=max_text_features,
            ngram_range=(1, 2)
        )
        self.is_fitted = False
        
        # Threat indicators
        self.urgent_keywords = ['urgent', 'immediate', 'action required', 'suspend', 'verify', 'attention']
        self.financial_keywords = ['invoice', 'payment', 'bank', 'wire', 'transfer', 'remittance', 'account']
        
        # Malicious extensions
        self.malicious_exts = ['.exe', '.vbs', '.scr', '.js', '.bat', '.cmd', '.zip']
        
    def _extract_text_heuristics(self, text):
        text_lower = str(text).lower()
        has_urgent = int(any(k in text_lower for k in self.urgent_keywords))
        has_financial = int(any(k in text_lower for k in self.financial_keywords))
        return has_urgent, has_financial

    def _extract_attachment_risk(self, ext):
        ext_lower = str(ext).lower()
        return int(ext_lower in self.malicious_exts)

    def fit_transform(self, df):
        # 1. Text processing (Subject + Body)
        df['combined_text'] = df['subject'].fillna('') + " " + df['body'].fillna('')
        text_features = self.text_vectorizer.fit_transform(df['combined_text']).toarray()
        
        # Feature names for TF-IDF
        text_feature_names = [f"tfidf_{name}" for name in self.text_vectorizer.get_feature_names_out()]
        df_text = pd.DataFrame(text_features, columns=text_feature_names, index=df.index)
        
        # 2. Metadata / Heuristics
        heuristics = df['combined_text'].apply(self._extract_text_heuristics).tolist()
        df['has_urgent_kw'] = [h[0] for h in heuristics]
        df['has_financial_kw'] = [h[1] for h in heuristics]
        
        df['is_malicious_ext'] = df['attachment_ext'].apply(self._extract_attachment_risk)
        
        # Ensure numerical features are correct
        df['has_attachment'] = df['has_attachment'].astype(int)
        df['attachment_size_kb'] = df['attachment_size_kb'].fillna(0.0).astype(float)
        df['url_count'] = df['url_count'].fillna(0).astype(int)
        df['suspicious_url_count'] = df['suspicious_url_count'].fillna(0).astype(int)
        
        # Combine all features
        feature_cols = [
            'has_attachment', 'attachment_size_kb', 'url_count', 
            'suspicious_url_count', 'has_urgent_kw', 'has_financial_kw', 
            'is_malicious_ext'
        ]
        
        X = pd.concat([df[feature_cols], df_text], axis=1)
        self.is_fitted = True
        
        return X

    def transform(self, df):
        if not self.is_fitted:
            raise ValueError("Extractor must be fitted before calling transform.")
            
        df['combined_text'] = df['subject'].fillna('') + " " + df['body'].fillna('')
        text_features = self.text_vectorizer.transform(df['combined_text']).toarray()
        
        text_feature_names = [f"tfidf_{name}" for name in self.text_vectorizer.get_feature_names_out()]
        df_text = pd.DataFrame(text_features, columns=text_feature_names, index=df.index)
        
        heuristics = df['combined_text'].apply(self._extract_text_heuristics).tolist()
        df['has_urgent_kw'] = [h[0] for h in heuristics]
        df['has_financial_kw'] = [h[1] for h in heuristics]
        df['is_malicious_ext'] = df['attachment_ext'].apply(self._extract_attachment_risk)
        
        # Fill missing numeric just in case
        df['has_attachment'] = df['has_attachment'].fillna(0).astype(int)
        df['attachment_size_kb'] = df['attachment_size_kb'].fillna(0.0).astype(float)
        df['url_count'] = df['url_count'].fillna(0).astype(int)
        df['suspicious_url_count'] = df['suspicious_url_count'].fillna(0).astype(int)
        
        feature_cols = [
            'has_attachment', 'attachment_size_kb', 'url_count', 
            'suspicious_url_count', 'has_urgent_kw', 'has_financial_kw', 
            'is_malicious_ext'
        ]
        
        X = pd.concat([df[feature_cols], df_text], axis=1)
        return X
