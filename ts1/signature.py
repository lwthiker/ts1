import json
import base64
import hashlib


class BytesJSONEncoder(json.JSONEncoder):
    """
    A JSON encoder that can handle bytes objects by encoding them in base64.
    """

    def default(self, o):
        # Encode byte objects to base64
        if type(o) is bytes:
            return base64.b64encode(o).decode("ascii")

        return json.JSONEncoder.default(self, o)


class Signature:
    """
    Abstract class that represents a network client's signature.
    """

    def to_dict(self):
        raise NotImplementedError()

    def to_json(self, **kwargs):
        """Serialize the signature to JSON format.

        Parameters
        ----------
        kwargs : dict
            Additional arguments to json.dumps()
        """
        return BytesJSONEncoder(**kwargs).encode(self.to_dict())

    def canonicalize(self):
        """Return the canonical form of this signature.

        The canonical form is a string that can be compared with other
        canonicalized strings. Two canonical strings are identical if the the
        underlying signature are identical and vice versa.

        The canonical form is the JSON encoding of the dict
        form, with keys ordered alphabetically, byte objects encoded with bas64
        and a single space after separators.
        """
        return BytesJSONEncoder(
            sort_keys=True,
            indent=None,
            separators=(", ", ": ")
        ).encode(self.to_dict())

    def hash(self):
        """Return a hash encoding all the information in the signature.

        The hash is SHA1 of the signature's canonical form as created by
        Signature.canonicalize()

        Returns
        -------
        hash
            Hash object as returned from hashlib
        """
        return hashlib.sha1(self.canonicalize().encode("utf-8"))
