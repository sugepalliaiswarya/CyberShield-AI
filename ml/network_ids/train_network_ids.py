import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib


print("Creating network intrusion dataset...")


data = {
    "packet_count": [
        20, 25, 30, 35, 40,
        100, 120, 150, 180, 200,
        22, 28, 32, 38, 45,
        110, 140, 160, 190, 220
    ],

    "connection_duration": [
        10, 12, 15, 18, 20,
        2, 3, 4, 5, 6,
        11, 14, 16, 19, 21,
        2, 3, 5, 6, 7
    ],

    "failed_connections": [
        0, 0, 1, 0, 1,
        8, 10, 12, 15, 18,
        0, 1, 0, 1, 0,
        9, 11, 14, 16, 20
    ],

    "bytes_sent": [
        500, 600, 700, 800, 900,
        5000, 6000, 7000, 8000, 9000,
        550, 650, 750, 850, 950,
        5500, 6500, 7500, 8500, 9500
    ],

    "bytes_received": [
        700, 800, 900, 1000, 1100,
        200, 250, 300, 350, 400,
        750, 850, 950, 1050, 1150,
        220, 270, 320, 370, 420
    ],

    "suspicious_port": [
        0, 0, 0, 0, 0,
        1, 1, 1, 1, 1,
        0, 0, 0, 0, 0,
        1, 1, 1, 1, 1
    ],

    "label": [
        0, 0, 0, 0, 0,
        1, 1, 1, 1, 1,
        0, 0, 0, 0, 0,
        1, 1, 1, 1, 1
    ]
}


df = pd.DataFrame(data)


print("Dataset created successfully!")
print("Dataset shape:", df.shape)


X = df.drop("label", axis=1)
y = df["label"]


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


print("Training Network IDS model...")


model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


model.fit(X_train, y_train)


print("Model training completed!")


y_pred = model.predict(X_test)


accuracy = accuracy_score(y_test, y_pred)


print("\nNetwork IDS Accuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


joblib.dump(
    model,
    "network_ids_model.pkl"
)


print("\nNetwork IDS model saved successfully!")
print("File: network_ids_model.pkl")