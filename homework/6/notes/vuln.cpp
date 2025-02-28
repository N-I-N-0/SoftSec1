#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

[[noreturn]] static void die(const char *message) {
    printf("\n%s\n", message);
    _Exit(1);
}

constexpr size_t NOTE_TITLE_SIZE = 32;
constexpr size_t NOTE_CONTENT_SIZE = 96;
constexpr size_t LINE_SIZE = 256;
constexpr size_t MAX_NOTES = 1000;

constexpr const char *LINE = "────────────────────────────────────────────────────────────────────────────────";

static_assert(LINE_SIZE >= NOTE_TITLE_SIZE, "Can't ever read a full note title");
static_assert(LINE_SIZE >= NOTE_CONTENT_SIZE, "Can't ever read the full note contents");
static std::array<char, LINE_SIZE> prompt_user(const char *prompt) {
    std::array<char, LINE_SIZE> buffer;

    printf("%s", prompt);
    if (!fgets(buffer.data(), buffer.size(), stdin))
        die("No input");

    size_t input_len = strlen(buffer.data());
    if (buffer[input_len - 1] == '\n')
        buffer[input_len - 1] = '\0';

    return buffer;
}

struct Note {
    time_t                              created;
    std::array<char, NOTE_TITLE_SIZE>   title;
    std::array<char, NOTE_CONTENT_SIZE> contents;

    Note() : created(time(nullptr)) {}

    void print() const {
        std::array<char, 40> ctime;
        strftime(ctime.data(), ctime.size(), "%F %T UTC", gmtime(&created));
        puts(LINE);
        printf("# %-32s %45s\n\n", title.data(), ctime.data());
        printf("%s\n\n", contents.data());
    }
};

class Notepad {
    std::vector<std::unique_ptr<Note>> notes;

    template <typename Title> auto find_note(Title &title) {
        return std::find_if(notes.begin(), notes.end(), [&title](const auto &n) {
            return strcmp(n->title.data(), title.data()) == 0;
        });
    }

public:
    void list() {
        printf("You currently have %ld note%s\n", notes.size(), notes.size() == 1 ? "" : "s");
        for (const auto &note : notes)
            note->print();
        if (!notes.empty())
            puts(LINE);
    }

    void add() {
        if (notes.size() >= MAX_NOTES)
            return (void) puts("Too many notes");
        auto title = prompt_user("Note title: ");
        if (strlen(title.data()) > NOTE_TITLE_SIZE)
            return (void) puts("Note title too long");
        if (find_note(title) != notes.end())
            return (void) puts("Note already exists");

        auto contents = prompt_user("Contents: ");
        if (strlen(contents.data()) > NOTE_CONTENT_SIZE)
            return (void) puts("Note contents too long");

        auto note = std::make_unique<Note>();
        strcpy(note->title.data(), title.data());
        strcpy(note->contents.data(), contents.data());
        notes.push_back(std::move(note));
    }

    void update() {
        auto title = prompt_user("Note title: ");
        if (strlen(title.data()) > NOTE_TITLE_SIZE)
            return (void) puts("Note title too long");

        auto it = find_note(title);
        if (it == notes.end())
            return (void) puts("No such note");

        auto contents = prompt_user("New contents: ");
        if (strlen(contents.data()) > NOTE_CONTENT_SIZE)
            return (void) puts("Note contents too long");

        strcpy((*it)->contents.data(), contents.data());
    }

    void duplicate() {
        if (notes.size() >= MAX_NOTES)
            return (void) puts("Too many notes");

        auto title = prompt_user("Note title: ");
        if (strlen(title.data()) > NOTE_TITLE_SIZE)
            return (void) puts("Note title too long");

        auto it = find_note(title);
        if (it == notes.end())
            return (void) puts("No such note");

        title = prompt_user("New title: ");
        if (strlen(title.data()) > NOTE_TITLE_SIZE)
            return (void) puts("Note title too long");

        if (find_note(title) != notes.end())
            return (void) puts("Note already exists");

        const auto *source = it->get();
        notes.reserve(notes.size() + 1);
        auto note = std::make_unique<Note>();
        memcpy(note.get(), source, sizeof(Note));
        memcpy(note->title.data(), title.data(), strlen(title.data()));
        notes.push_back(std::move(note));
    }
};


int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    puts("Welcome to my note taking service, please don't hack it");
    puts("You can");
    puts(" - [Q]uit");
    puts(" - [L]ist all notes");
    puts(" - [A]dd a note");
    puts(" - [U]pdate a note");
    puts(" - [D]uplicate a note");
    Notepad notes;
    for (;;) {
        switch (prompt_user("> ")[0]) {
            case 'q': case 'Q': puts("Bye"); return 0;
            case 'l': case 'L': notes.list(); break;
            case 'a': case 'A': notes.add(); break;
            case 'u': case 'U': notes.update(); break;
            case 'd': case 'D': notes.duplicate(); break;
            default: puts("Invalid input"); break;
        }
    }
}
