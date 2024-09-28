# extended_label_encoder.py

import numpy as np
from sklearn.preprocessing import LabelEncoder

class ExtendedLabelEncoder(LabelEncoder):
    def __init__(self):
        super().__init__()
        self.fitted_classes = set()

    def fit(self, y):
        super().fit(y)
        self.fitted_classes = set(self.classes_)
        return self

    def transform(self, y):
        new_labels = set(y) - self.fitted_classes
        if new_labels:
            new_classes = list(self.classes_) + list(new_labels)
            self.classes_ = np.array(new_classes)
        return super().transform(y)

    def fit_transform(self, y):
        return self.fit(y).transform(y)
