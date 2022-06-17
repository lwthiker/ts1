from typing import List, Dict, Tuple

from ts1.signature import Signature
from ts1.utils import NghttpdLogParser


class HTTP2FrameSignature(Signature):

    # A registry of subclasses
    registry = {}

    def __init__(self, frame_type: str, stream_id: int):
        self.frame_type = frame_type
        self.stream_id = stream_id

    def __init_subclass__(cls, /, frame_type: str, **kwargs):
        """Register subclasses to the registry"""
        super().__init_subclass__(**kwargs)
        cls.registry[frame_type] = cls
        cls.frame_type = frame_type

    def to_dict(self):
        d = {
            "frame_type": self.frame_type
        }
        if self.stream_id is not None:
            d["stream_id"] = self.stream_id
        return d

    @classmethod
    def from_dict(cls, d):
        """Unserialize an HTTP2FrameSignature from a dict.

        Initializes the suitable subclass if exists, otherwise initializes
        an HTTP2FrameSignature proper instance.
        """
        d = d.copy()
        frame_type = d.pop("frame_type")
        if frame_type in cls.registry:
            return cls.registry[frame_type].from_dict(d)
        else:
            return HTTP2FrameSignature(frame_type=frame_type)


class HTTP2SettingsFrame(HTTP2FrameSignature, frame_type="SETTINGS"):
    # Some browsers (e.g. Chrome 98) added a non-existent, randomly-generated
    # settings key to the SETTINGS frame. This is denoted as HTTP2_GREASE due
    # to similarity with TLS GREASE
    HTTP2_GREASE = "GREASE"

    # See RFC7540, section "Defined SETTINGS parameters"
    VALID_SETTINGS = [1, 2, 3, 4, 5, 6]

    def __init__(self, stream_id: int, settings: List[Tuple]):
        super().__init__(self.frame_type, stream_id)
        self.settings = []
        for (k, v) in settings:
            if k not in self.VALID_SETTINGS:
                k = self.HTTP2_GREASE
            if k == self.HTTP2_GREASE:
                v = self.HTTP2_GREASE
            self.settings.append({
                "id": k,
                "value": v
            })

    def to_dict(self):
        d = super().to_dict()
        d["settings"] = self.settings
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return HTTP2SettingsFrame(
            stream_id=d.get("stream_id"),
            settings=d["settings"]
        )


class HTTP2WindowUpdateFrame(HTTP2FrameSignature, frame_type="WINDOW_UPDATE"):
    def __init__(self, stream_id: int, window_size_increment: int):
        super().__init__(self.frame_type, stream_id)
        self.window_size_increment = window_size_increment

    def to_dict(self):
        d = super().to_dict()
        d["window_size_increment"] = self.window_size_increment
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return HTTP2WindowUpdateFrame(
            stream_id=d.get("stream_id"),
            window_size_increment=d["window_size_increment"]
        )


class HTTP2HeadersFrame(HTTP2FrameSignature, frame_type="HEADERS"):
    def __init__(self, stream_id: int, pseudo_headers: List[str]):
        super().__init__(self.frame_type, stream_id)
        self.pseudo_headers = pseudo_headers

    def to_dict(self):
        d = super().to_dict()
        d["pseudo_headers"] = self.pseudo_headers
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return HTTP2HeadersFrame(
            stream_id=d.get("stream_id"),
            pseudo_headers=d["pseudo_headers"]
        )


class HTTP2PriorityFrame(HTTP2FrameSignature, frame_type="PRIORITY"):
    def __init__(self,
                 stream_id: int,
                 dep_stream_id: int,
                 weight: int,
                 exclusive: bool):
        super().__init__(self.frame_type, stream_id)
        self.priority = {
            "dep_stream_id": dep_stream_id,
            "weight": weight,
            "exclusive": exclusive
        }

    def to_dict(self):
        d = super().to_dict()
        d["priority"] = self.priority
        return d

    @classmethod
    def from_dict(cls, d: dict):
        return HTTP2PriorityFrame(
            stream_id=d.get("stream_id"),
            **d["priority"]
        )


class HTTP2Signature(Signature):
    """
    Signature of an HTTP/2 client.

    Combines the first frames sent by the client during the initial phase of
    the HTTP/2 connection to form a signature, which can then be compared with
    other client's signature to identify whether it originated from a similar
    client.

    The signature includes all the frames up to, and including, the first
    HEADERS frame sent by the client. The HEADERS frame is recorded partially,
    excluding the actual HTTP headers, as the focus of this class is on HTTP/2
    only parameters.
    """

    def __init__(self, frames: List[HTTP2FrameSignature]):
        """
        Initialize a new HTTP2Signature.

        Signatures can be compared with one another to check if they are equal.

        Paramaeters
        -----------
        frames: list[HTTP2FrameSignature]
            List of frames sent by the client during the initial phase of the
            HTTP/2 connections. The frames recorded are all the frames up to,
            and including, the HEADERS frame.
        """
        self.frames = frames

    def to_dict(self):
        """Serialize to a dict object."""
        return {
            "frames": [frame.to_dict() for frame in self.frames]
        }

    @classmethod
    def from_dict(cls, d):
        """Unserialize HTTP2Signature from a dict.

        Parameters
        ----------
        d : dict
            HTTP/2 signature encoded to a Python dict, possibly by using
            HTTP2Signature.to_dict()

        Returns
        -------
        sig : HTTP2Signature
            Signature constructed from the dict representation.
        """
        return HTTP2Signature(
            frames=[
                HTTP2FrameSignature.from_dict(frame) for frame in d["frames"]
            ]
        )


def process_nghttpd_log(log: str) -> List[Dict]:
    """Parse nghttpd's log to extract HTTP/2 client signatures.

    Parameters
    ----------
    log : str
        nghttpd's output when given the '-v' flag.

    Returns
    -------
    sigs : list[HTTP2Signature]
        List of clients and their HTTP/2 signatures as detected in the log.
        Each entry contains "client_id", a numerical identifier of the client,
        and "signature", a HTTP2Signature object containing the client's
        signature.
    """
    return [
        {
            "client_id": client_id,
            "signature": HTTP2Signature.from_dict({"frames": frames})
        }
        for client_id, frames in NghttpdLogParser(log).parse().items()
    ]
