import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin


class CweEncoder(BaseEstimator, TransformerMixin):
    """
    Multi-hot encodes the ";"-separated CWE field.

    The list of CWEs to keep (most frequent top_n) is learned in fit(),
    i.e. from the training years only. Any other CWE sets "cwe_other".
    """

    def __init__(self, top_n=25):
        self.top_n = top_n

    def _exploded(self, X):
        # One row per (record position, CWE); empty CWE fields dropped.
        # (str.get_dummies is far slower on large frames.)
        values = X.iloc[:, 0] if isinstance(X, pd.DataFrame) else pd.Series(X)
        values = values.reset_index(drop=True)
        exploded = values.fillna("").astype(str).str.split(";").explode()
        return exploded[exploded != ""], len(values)

    def fit(self, X, y=None):
        exploded, _ = self._exploded(X)
        self.cwes_ = exploded.value_counts().index[: self.top_n].tolist()
        return self

    def transform(self, X):
        exploded, n_rows = self._exploded(X)

        known = exploded[exploded.isin(self.cwes_)]

        out = pd.crosstab(known.index, known).reindex(
            index=range(n_rows), columns=self.cwes_, fill_value=0
        ).clip(upper=1)
        out.columns = [f"cwe_{c}" for c in self.cwes_]
        out.columns.name = None

        other_rows = exploded.index[~exploded.isin(self.cwes_)].unique()
        out["cwe_other"] = 0
        out.loc[other_rows, "cwe_other"] = 1

        out.index = X.index if isinstance(X, pd.DataFrame) else out.index

        return out

    def get_feature_names_out(self, input_features=None):
        return np.array([f"cwe_{c}" for c in self.cwes_] + ["cwe_other"])
