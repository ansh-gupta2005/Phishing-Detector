import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import json

def train_model(
    dataset_path='url_dataset.csv',
    model_path='phishing_rf_model.pkl',
    accuracy_path='model_metrics.json'
):
    # Load dataset
    df = pd.read_csv(dataset_path)

    # Assuming 'label' column is the target: 0 = safe, 1 = phishing
    X = df.drop(columns=['label', 'url'], errors='ignore')  # drop 'url' if present
    y = df['label']

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Initialize Random Forest classifier
    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    # Train the model
    clf.fit(X_train, y_train)

    # Predict on test set
    y_pred = clf.predict(X_test)

    # Calculate accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model accuracy: {accuracy*100:.2f}%")

    # Save classification report as dictionary
    class_report = classification_report(y_test, y_pred, output_dict=True)

    # Save accuracy and report to JSON
    metrics = {
        "accuracy": accuracy,
        "classification_report": class_report
    }
    with open(accuracy_path, "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"Saved metrics to {accuracy_path}")

    # Save the trained model to file
    joblib.dump(clf, model_path)
    print(f"Saved model to {model_path}")


if __name__ == "__main__":
    # You can change dataset/model/metrics paths here if needed
    train_model()
