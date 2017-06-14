// RUN: %clang_cc1 -analyze -analyzer-checker=mesos.option %s -verify

template <typename T>
struct Option {
  const T &get() const;

  bool isSome() const;
  bool isNone() const;
};

int f1(const Option<int> &option) {
  return option.get(); // expected-warning{{unchecked use of Option value}}
}

void f2(const Option<int> &option) {
  if (option.isSome()) {
    option.get(); // OK.
  } else {
    option.get(); // expected-warning{{get called on empty Option}}
  }
}

void f3(const Option<int> &option) {
  if (option.isNone()) {
    option.get(); // expected-warning{{get called on empty Option}}
  } else {
    option.get(); // OK.
  }
}

void f4(Option<int> option1, Option<int> option2) {
  if (option1.isSome()) {
    option2.get(); // expected-warning{{unchecked use of Option value}}

    option2 = option1;
    option2.get(); // OK.
  }
}

