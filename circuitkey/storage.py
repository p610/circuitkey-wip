import json
import os

import adafruit_logging as logging

log = logging.getLogger(__name__)


def reset():
    if os.path.exists("data"):
        os.rmdir("data")


class Bucket:
    def __init__(self, filename: str):
        if not filename.endswith(".json"):
            raise ValueError("File must be a .json file")

        if not os.path.exists("data"):
            os.mkdir("data")

        self.path = os.path.join("data", filename)

    def load(self):
        with open(self.path, "r") as f:
            data = f.read()
            if len(data) == 0:
                return {}
            return json.load(data)

    def save(self, data):
        with open(self.path, "w") as f:
            f.write(json.dumps(data))


class CounterBucket(Bucket):
    def __init__(self):
        super().__init__("counter.json")

    def increment(self):
        data = self.load()
        data["counter"] += 1
        self.save(data)

    def get(self):
        return self.load()["counter"]

    def reset(self):
        self.save({"counter": 0})


class PinBucket(Bucket):
    def __init__(self):
        super().__init__("pin.json")


class KeyBucket(Bucket):
    def __init__(self):
        super().__init__("keys.json")

    def add(self, key):
        data = self.load()
        data[key] = True
        self.save(data)

    def remove(self, key):
        data = self.load()
        data.pop(key)
        self.save(data)

    def contains(self, key):
        return key in self.load()

    def get(self):
        return self.load()
