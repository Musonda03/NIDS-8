import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from extended_label_encoder import ExtendedLabelEncoder
import os

# Load the new dataset
new_data_path = 'new_packets.csv'
df_new = pd.read_csv(new_data_path)

# Ensure all necessary columns are present
required_columns = ['timestamp', 'ip_src', 'ip_dst', 'ip_proto', 'sport', 'dport', 'tcp_flags', 'label']
if not all(column in df_new.columns for column in required_columns):
    raise ValueError(f"New dataset must contain the following columns: {required_columns}")

# Load the original dataset (if available) to merge with the new dataset
original_data_path = 'original_dataset.csv'
if os.path.exists(original_data_path):
    df_original = pd.read_csv(original_data_path)
    df_combined = pd.concat([df_original, df_new], ignore_index=True)
else:
    df_combined = df_new

# Encode categorical features
label_encoder = ExtendedLabelEncoder()
df_combined['ip_src'] = label_encoder.fit_transform(df_combined['ip_src'])
df_combined['ip_dst'] = label_encoder.fit_transform(df_combined['ip_dst'])
df_combined['tcp_flags'] = label_encoder.fit_transform(df_combined['tcp_flags'])

# Separate features and labels
X = df_combined.drop(columns=['label'])
y = df_combined['label']

# Train a new model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save the updated model and label encoder
joblib.dump(model, 'random_forest_model.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')

print("Model updated successfully.")
