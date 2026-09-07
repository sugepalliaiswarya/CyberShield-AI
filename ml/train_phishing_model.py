from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib


print("Downloading phishing dataset...")

# Fetch UCI Phishing Websites dataset
phishing_websites = fetch_ucirepo(id=327)

X = phishing_websites.data.features
y = phishing_websites.data.targets

print("Dataset downloaded successfully!")
print("Features:", X.shape)
print("Target:", y.shape)


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training Random Forest model...")


# Create model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)


# Train model
model.fit(X_train, y_train.values.ravel())

print("Model training completed!")


# Test model
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# Save model
joblib.dump(model, "ml/phishing_model.pkl")

print("\nModel saved successfully!")
print("Location: ml/phishing_model.pkl")