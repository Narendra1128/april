import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import pickle

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier

from sklearn.svm import SVC

data0 = pd.read_csv('./Data Files/final_dataset.csv')

# Plotting the data distribution
data0.hist(bins=50, figsize=(15, 18))
# plt.show()

plt.figure(figsize=(15, 13))
sns.heatmap(data0.corr())
# plt.show()

# Dropping the Domain column
data = data0.drop(['Domain'], axis=1).copy()

# checking the data for null or missing values
# print(data.isnull().sum())

# shuffling the rows in the dataset so that when splitting the train and test set are equally distributed
data = data.sample(frac=1).reset_index(drop=True)
# print(data.head())

# Sepratating & assigning features and target columns to X & y
y = data['Label']  # output from training
X = data.drop('Label', axis=1)  # input for training
# print(X.shape, y.shape)

# < ----------------------------------------------------------------------------------------------------------------------- >/#

# Splitting the dataset into train and test sets: 80-20 split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=12)
# print(X_train.shape, X_test.shape)


# Creating holders to store the model performance results
ML_Model = []
acc_train = []
acc_test = []


# function to call for storing the results
def storeResults(model, a, b):
    ML_Model.append(model)
    acc_train.append(round(a, 3))
    acc_test.append(round(b, 3))

# < ----------------------------------------------------------------------------------------------------------------------- >/#

# Decision Tree model
# instantiate the model
tree = DecisionTreeClassifier(max_depth=5)
# fit the model
tree.fit(X_train, y_train)

# predicting the target value from the model for the samples
y_test_tree = tree.predict(X_test)
y_train_tree = tree.predict(X_train)

# computing the accuracy of the model performance
acc_train_tree = accuracy_score(y_train, y_train_tree)
acc_test_tree = accuracy_score(y_test, y_test_tree)

print("Decision Tree: Accuracy on training Data: {:.3f}".format(acc_train_tree))
print("Decision Tree: Accuracy on test Data: {:.3f}".format(acc_test_tree))

# checking the feature importance in the model
plt.figure(figsize=(9, 7))
n_features = X_train.shape[1]
plt.barh(range(n_features), tree.feature_importances_, align='center')
plt.yticks(np.arange(n_features), X_train.columns)
plt.xlabel("Feature importance")
plt.ylabel("Feature")
# plt.show()

# storing the results. The below mentioned order of parameter passing is important.
# Caution: Execute only once to avoid duplications.
storeResults('Decision Tree', acc_train_tree, acc_test_tree)

# < ----------------------------------------------------------------------------------------------------------------------- >/#

# Random Forest model
# instantiate the model
forest = RandomForestClassifier(max_depth=5)

# fit the model
forest.fit(X_train, y_train)
# predicting the target value from the model for the samples
y_test_forest = forest.predict(X_test)
y_train_forest = forest.predict(X_train)

# computing the accuracy of the model performance
acc_train_forest = accuracy_score(y_train, y_train_forest)
acc_test_forest = accuracy_score(y_test, y_test_forest)

print("Random forest: Accuracy on training Data: {:.3f}".format(acc_train_forest))
print("Random forest: Accuracy on test Data: {:.3f}".format(acc_test_forest))

# checking the feature importance in the model
plt.figure(figsize=(9, 7))
n_features = X_train.shape[1]
plt.barh(range(n_features), forest.feature_importances_, align='center')
plt.yticks(np.arange(n_features), X_train.columns)
plt.xlabel("Feature importance")
plt.ylabel("Feature")
# plt.show()

# Caution: Execute only once to avoid duplications.
storeResults('Random Forest', acc_train_forest, acc_test_forest)

# < ----------------------------------------------------------------------------------------------------------------------- >/#

# instantiate the model
mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100, 100, 100]))

# fit the model
mlp.fit(X_train, y_train)

# predicting the target value from the model for the samples
y_test_mlp = mlp.predict(X_test)
y_train_mlp = mlp.predict(X_train)

# computing the accuracy of the model performance
acc_train_mlp = accuracy_score(y_train, y_train_mlp)
acc_test_mlp = accuracy_score(y_test, y_test_mlp)

print("Multilayer Perceptrons: Accuracy on training Data: {:.3f}".format(acc_train_mlp))
print("Multilayer Perceptrons: Accuracy on test Data: {:.3f}".format(acc_test_mlp))

storeResults('Multilayer Perceptrons', acc_train_mlp, acc_test_mlp)

# instantiate the model
xgb = XGBClassifier(learning_rate=0.4, max_depth=7)
# fit the model
xgb.fit(X_train, y_train)

# predicting the target value from the model for the samples
y_test_xgb = xgb.predict(X_test)
y_train_xgb = xgb.predict(X_train)

# computing the accuracy of the model performance
acc_train_xgb = accuracy_score(y_train, y_train_xgb)
acc_test_xgb = accuracy_score(y_test, y_test_xgb)

print("XGBoost: Accuracy on training Data: {:.3f}".format(acc_train_xgb))
print("XGBoost : Accuracy on test Data: {:.3f}".format(acc_test_xgb))

storeResults('XGBoost', acc_train_xgb, acc_test_xgb)

# < ----------------------------------------------------------------------------------------------------------------------- >/#

# Support vector machine model
# instantiate the model
svm = SVC(kernel='linear', C=1.0, random_state=12)
# fit the model
svm.fit(X_train, y_train)

# predicting the target value from the model for the samples
y_test_svm = svm.predict(X_test)
y_train_svm = svm.predict(X_train)

# computing the accuracy of the model performance
acc_train_svm = accuracy_score(y_train, y_train_svm)
acc_test_svm = accuracy_score(y_test, y_test_svm)

print("SVM: Accuracy on training Data: {:.3f}".format(acc_train_svm))
print("SVM : Accuracy on test Data: {:.3f}".format(acc_test_svm))

storeResults('SVM', acc_train_svm, acc_test_svm)

# < ----------------------------------------------------------------------------------------------------------------------- >/#

# creating dataframe
results = pd.DataFrame({'ML Model': ML_Model,
                        'Train Accuracy': acc_train,
                        'Test Accuracy': acc_test})

# print(results)
sorted = results.sort_values(by=['Train Accuracy', 'Test Accuracy'], ascending=False)

print(sorted)

sorted.to_csv('results1.csv', index=False)
pickle.dump(xgb, open("model3.pickle.dat", "wb"))

loaded_model = pickle.load(open("model3.pickle.dat", "rb"))
print(loaded_model)

