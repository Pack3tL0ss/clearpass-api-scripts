from pushbullet import Pushbullet


class Push:
    def __init__(self, pb_key: str = None):
        self.pb = Pushbullet(pb_key)

    def sendpush(self, title: str = None, body: str = None, **kwargs) -> dict:
        # def push_note(self, title, body, device=None, chat=None, email=None, channel=None):
        if title and not body:
            title = "ClearPass API"
            body = title

        return self.pb.push_note(title, body, **kwargs)
