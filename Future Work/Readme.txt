The folder includes the Future work section in the report. It includes applying the same model building strategy but for a public imbalanced dataset called InSDN.

Here we focus on spliting the dataset (80%-20%) set first and then balance the training set only. Unlike most papers we read they balance the whole training set to have 

equal distribution across all classes (normal and attacks like DDoS, Web attack, BFA, etc..) using balacing algorthims like SMOTE. The Problem is for Minority classes this 

would introduce a lot of noisy point in the dataset so that the minor class would match the majority class in distribution. We focus on using the balancing algorithm to

increase the minority class by 10 - 20% from the majority class.

