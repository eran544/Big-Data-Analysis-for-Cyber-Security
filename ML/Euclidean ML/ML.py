
import pandas as pd
import matplotlib.pyplot as plt
from sklearn import svm, datasets, metrics
from sklearn.tree import _tree
from sklearn.tree import DecisionTreeClassifier, plot_tree
import six
import sys
sys.modules['sklearn.externals.six'] = six
import numpy as np
from sklearn.tree import export_graphviz
import pydotplus
import os
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score


def LogisticRegression_Classifier(logmodel):
    def ML_LogisticRegression( X_train, X_test, Y_train, Y_test):
        fileML = open("Ml data.txt", "a+")  # append mode
        # logmodel = LogisticRegression(penalty=Penalty,  # l2 and l2
        #                               solver='liblinear',
        #                               max_iter=Max_iter )
        result = logmodel.fit(X_train, Y_train)
        probs = logmodel.predict_proba(X_test)
        preds = probs[:,1]
        # print(preds)
        fpr, tpr, threshold = metrics.roc_curve(Y_test, preds)
        roc_auc = metrics.auc(fpr, tpr)
        plt.title('Receiver Operating Characteristic-Logistic Regression')
        plt.plot(fpr, tpr, 'b', label='AUC = %0.2f' % roc_auc)
        plt.legend(loc='lower right')
        plt.plot([0, 1], [0, 1], 'r--')
        plt.xlim([0, 1])
        plt.ylim([0, 1])
        plt.ylabel('True Positive Rate')
        plt.xlabel('False Positive Rate')

        path = os.path.join(parent_dir, "Logistic Regression")
        plt.savefig(path)
        plt.show()
        print('finished Logistic Regression')


        fileML.write("Logistic Regression coeff: \n")
        for i in range(len(logmodel.coef_[0])):
            print(X_train.columns[i])
            fileML.write("{0}: ".format(X_train.columns[i]))
            print("coeff: " + str(logmodel.coef_[0][i]))
            fileML.write("coeff: {0} ,".format(str(logmodel.coef_[0][i])))
            print("2^coeff: " + str(2.0**(logmodel.coef_[0][i])))
            fileML.write("2^coeff: {0} \n".format(str(2.0**(logmodel.coef_[0][i]))))

        fileML.write("------------------------------------------\n")
        fileML.close()
    return ML_LogisticRegression


def Decision_Tree_Classifier(clf):
    def ML_tree( X_train, X_test, Y_train, Y_test):
         fileML = open("Ml data.txt", "a+")  # append mode
         def tree_to_code(tree, feature_names):
            tree_ = tree.tree_
            feature_name = [
                feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
                for i in tree_.feature]

            print ("def tree({}):\n".format(", ".join(feature_names)))
            fileML.write("def tree({}):\n".format(", ".join(feature_names)))

            def recurse(node, depth):
                indent = "  " * depth
                if tree_.feature[node] != _tree.TREE_UNDEFINED:
                    name = feature_name[node]
                    threshold = tree_.threshold[node]
                    print("{}if {} <= {}:\n".format(indent, name, threshold))
                    fileML.write("{}if {} <= {}:\n".format(indent, name, threshold))
                    recurse(tree_.children_left[node], depth + 1)
                    print("{}else:  # if {} > {}\n".format(indent, name, threshold))
                    fileML.write("{}else:  # if {} > {}\n".format(indent, name, threshold))
                    recurse(tree_.children_right[node], depth + 1)
                else:
                    print("{}return {}\n".format(indent, tree_.value[node]))
                    fileML.write("{}return {}\n".format(indent, tree_.value[node]))

            recurse(0, 1)
            fileML.write("\n")
            # clf = DecisionTreeClassifier().fit(iris.data, iris.target)
            plot_tree(tree, filled=True)
            plt.show()
         clf = DecisionTreeClassifier(random_state=0, max_depth=10, min_samples_leaf=1)
         result = clf.fit(X_train, Y_train)

         probs = clf.predict_proba(X_test)
         preds = probs[:, 1]
         fpr, tpr, threshold = metrics.roc_curve(Y_test, preds)
         roc_auc = metrics.auc(fpr, tpr)

         #---------print----------------------------------------------
         # ----------tree----------------
         print(clf.feature_importances_)
         fileML.write("Euclidean Decision Tree Classifier feature_importances: \n")
         for i in range(len(clf.feature_importances_)):
             print(X_train.columns[i])
             fileML.write("{0}: ".format(X_train.columns[i]))
             print(clf.feature_importances_[i])
             fileML.write("{0} \n".format(clf.feature_importances_[i]))
             print("2^coeff: " + str(2.0 ** (clf.feature_importances_[i])))
             fileML.write("2^coeff: {0} \n".format(str(2.0 ** (clf.feature_importances_[i]))))

         fileML.write("\n")

         dot_data = six.StringIO()
         export_graphviz(clf, out_file=dot_data,
                         feature_names=X_train.columns,
                         filled=True, rounded=True,
                         special_characters=True)
         graph = pydotplus.graph_from_dot_data(dot_data.getvalue())
         graph.write_pdf("Decision Tree Classifier.pdf")

         # ----------grapgh---------------------
         # method I: plt
         plt.title('Euclidean Receiver Operating Characteristic-Decision Tree')
         plt.plot(fpr, tpr, 'b', label='AUC = %0.2f' % roc_auc)
         plt.legend(loc='lower right')
         plt.plot([0, 1], [0, 1], 'r--')
         plt.xlim([0, 1])
         plt.ylim([0, 1])
         plt.ylabel('True Positive Rate')
         plt.xlabel('False Positive Rate')
         path = os.path.join(parent_dir, "Decision Tree Classifier")
         plt.savefig(path)
         plt.show()
         print('finished')

         #----------function---------
         tree_to_code(clf,      ["Malicious", "Day count Mean", "Day count STD", 'max Day count', "Size",
     "Euclidean 15-Malicious(%)","Euclidean 10-Malicious(%)","Euclidean 5-Malicious(%)",
     "Prevalence", "Peaks", "Sharp peaks"
     ])

         fileML.write("----------------------------------------------\n")
         fileML.close()
    return ML_tree

#return the best function after cross val
def crossVal(X_train,Y_train):
    # Use cross_val_score on your all data
    # internal working of cross_val_predict:
    # 1. Get the data and estimator (logreg, X, Y)
    # 2. Split X, Y into X_train, X_test, Y_train, Y_test by using its internal cv
    # 3. Use X_train, Y_train for fitting 'logreg': Y_pred = logreg.predict(X_test) and calculate accuracy with Y_test.
    # 4. Repeat steps 1 to 3 for cv_iterations = 10
    # Return array of accuracies calculated in step 5.
    fileML = open("Ml data.txt", "a+")  # append mode
    fileML.write("Euclidean Cross Validation (5 fold):\n")

    #Logistic Regression cross_val
    name1="Logistic Regression(penalty='l2',solver='liblinear',max_iter=300)"
    fileML.write("1.1 {}: ".format(name1))
    logreg1 = LogisticRegression(penalty='l2',solver='liblinear',max_iter=300)
    scores_logreg1 = cross_val_score(logreg1, X_train, Y_train, cv=5)
    fileML.write(str(scores_logreg1))
    scores_logreg1 = scores_logreg1.mean()
    fileML.write(" => the avarage is {} \n".format(scores_logreg1))

    name2 = "Logistic Regression(penalty='l2', solver='liblinear', max_iter=500)"
    fileML.write("1.2 {}: ".format(name2))
    logreg2 = LogisticRegression(penalty='l2',
                                solver='liblinear',
                                max_iter=500)
    scores_logreg2 = cross_val_score(logreg2, X_train, Y_train, cv=5)
    fileML.write(str(scores_logreg2))
    scores_logreg2 = scores_logreg2.mean()
    fileML.write(" => the avarage is {} \n".format(scores_logreg2))


    # DecisionTree cross_val
    name3 = "TreeClassifier(random_state=0, max_depth=10, min_samples_leaf=1)"
    fileML.write("2.1 {}: ".format(name3))
    Dt1 = DecisionTreeClassifier(random_state=0, max_depth=10, min_samples_leaf=1)
    scores_Dt1 = cross_val_score(Dt1, X_train, Y_train, cv=5)
    fileML.write(str(scores_Dt1))
    scores_Dt1 = scores_Dt1.mean()
    fileML.write(" => the avarage is {} \n".format(scores_Dt1))

    name4 = "TreeClassifier(random_state=0, max_depth=3, min_samples_leaf=1)"
    fileML.write("2.2 {}: ".format(name4))
    Dt2 = DecisionTreeClassifier(random_state=0, max_depth=3, min_samples_leaf=1)
    scores_Dt2 = cross_val_score(Dt2, X_train, Y_train, cv=5)
    fileML.write(str(scores_Dt2))
    scores_Dt2 = scores_Dt2.mean()
    fileML.write(" => the avarage is {} \n".format(scores_Dt2))

    funcdict = [
      [name1, LogisticRegression_Classifier(logreg1)],
       [name2, LogisticRegression_Classifier(logreg2)],
       [name3, Decision_Tree_Classifier(Dt1)],
        [name4,Decision_Tree_Classifier(Dt2)]
        ]

    scors=np.array([scores_logreg1,scores_logreg2,scores_Dt1,scores_Dt2])
    bestFunc=funcdict[np.argmax(scors)]
    fileML.write(" => the best Classifier is {} \n".format(bestFunc[0]))
    fileML.write("----------------------------------------------\n")
    fileML.close()
    return bestFunc[1]



dfTrain = pd.read_csv('features Train.csv')
forMLTrain = dfTrain[
    ["Malicious", "Day count Mean", "Day count STD", 'max Day count', "Size",
     "Euclidean 15-Malicious(%)", "Euclidean 10-Malicious(%)", "Euclidean 5-Malicious(%)",
     "Prevalence", "Peaks", "Sharp peaks"
     ]
    ]
X_train=forMLTrain.drop('Malicious', axis=1)
Y_train=forMLTrain['Malicious']
parent_dir = os.getcwd()

chosen_func=crossVal(X_train,Y_train)

dfTest = pd.read_csv('features Test.csv')
forMLTest = dfTest[
    ["Malicious", "Day count Mean", "Day count STD", 'max Day count', "Size",
     "Euclidean 15-Malicious(%)","Euclidean 10-Malicious(%)","Euclidean 5-Malicious(%)",
     "Prevalence", "Peaks", "Sharp peaks"
     ]
]
X_test=forMLTest.drop('Malicious', axis=1)
Y_test=forMLTest['Malicious']
parent_dir = os.getcwd()
chosen_func( X_train, X_test, Y_train, Y_test)



# "Euclidean k-Malicious(%)"
# # ["Malicious", "Day count Mean", "Day count STD", 'max Day count', "Size", "DTW k-mean", "DTW k-median", "DTW k-STD",
# #  "DTW k-Malicious(%)", "Prevalence", "Peaks", "Sharp peaks",
# #  "min Day count", "Euclidean k-mean", "Euclidean k-median", "Euclidean k-STD", "Euclidean k-Malicious(%)"]
# # ]