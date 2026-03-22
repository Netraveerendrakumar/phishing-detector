import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

print("Loading dataset...")
df = pd.read_csv('data/phishing.csv')

print(f"Dataset shape: {df.shape}")
print(f"Columns: {list(df.columns)}")

# Drop index column if present
if 'Index' in df.columns:
    df = df.drop(columns=['Index'])

# Last column is the label (1 = phishing, -1 = legitimate)
X = df.iloc[:, :-1].values
y = df.iloc[:, -1].values

# Convert -1 labels to 0 for consistency (0=legit, 1=phishing)
y = np.where(y == -1, 0, y)

print(f"\nTotal samples  : {len(y)}")
print(f"Phishing       : {np.sum(y == 1)}")
print(f"Legitimate     : {np.sum(y == 0)}")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
print("\nTraining Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(f"\nAccuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model and column names
os.makedirs('model', exist_ok=True)
with open('model/phishing_model.pkl', 'wb') as f:
    pickle.dump(model, f)

# Save feature column names for use in app.py
feature_columns = list(df.columns[:-1])
with open('model/feature_columns.pkl', 'wb') as f:
    pickle.dump(feature_columns, f)

print("\nModel saved to model/phishing_model.pkl")
print(f"Features saved: {feature_columns}")