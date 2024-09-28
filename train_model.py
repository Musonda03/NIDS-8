# train_model.py

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# ExtendedLabelEncoder class definition
import numpy as np
from extended_label_encoder import ExtendedLabelEncoder

# Load your labeled dataset
csv_path = 'C:/Users/muson/Desktop/NIDS 8/captured_packets.csv' 
data = pd.read_csv(csv_path)  # Replace with your labeled dataset path

# Convert timestamp to numerical value (e.g., Unix epoch time)
data['timestamp'] = pd.to_datetime(data['timestamp'])
data['timestamp'] = data['timestamp'].astype('int64') // 10**9

# Use ExtendedLabelEncoder for categorical features
label_encoder = ExtendedLabelEncoder()
data['ip_src'] = label_encoder.fit_transform(data['ip_src'])
data['ip_dst'] = label_encoder.fit_transform(data['ip_dst'])
data['tcp_flags'] = label_encoder.fit_transform(data['tcp_flags'])

# Extract features and labels
X = data.drop(columns=['label', 'anomaly_flag'])
y = data['label']

# Convert labels to binary
y = y.map({'normal': 0, 'anomaly': 1})

# Split the dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Save a sample of anomalous data for testing
anomalous_sample = X_train[y_train == 1].head(10)
anomalous_sample.to_csv('anomalous_sample.csv', index=False)

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save the model and label encoders
joblib.dump(model, 'random_forest_model.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')

