//! Player tracking: match server output lines against the join/leave regexes
//! and keep the set of online players.

use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use regex::Regex;

use crate::config::PlayerRegexes;

/// A change in the online player set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayerEvent {
    /// A player joined and was not online before.
    Joined(String),
    /// A player left and was online before.
    Left(String),
}

/// Tracker holding the compiled regexes and the current player set.
pub struct PlayerTracker {
    regexes: PlayerRegexes,
    players: Mutex<HashSet<String>>,
}

impl PlayerTracker {
    /// Build a tracker from compiled regexes.
    #[must_use]
    pub fn new(regexes: PlayerRegexes) -> Self {
        Self {
            regexes,
            players: Mutex::new(HashSet::new()),
        }
    }

    /// Feed one output line to the tracker.
    ///
    /// Returns the event if the player set changed, `None` for non-matching
    /// lines and for redundant events like a repeated join or the leave of a
    /// player who is not online.
    pub fn parse_line(&self, line: &str) -> Option<PlayerEvent> {
        if let Some(name) = capture(&self.regexes.join, line) {
            let name = name.to_string();
            let mut players = self.lock();
            let inserted = players.insert(name.clone());
            drop(players);
            return inserted.then_some(PlayerEvent::Joined(name));
        }
        if let Some(name) = capture(&self.regexes.leave, line) {
            let name = name.to_string();
            let mut players = self.lock();
            let removed = players.remove(name.as_str());
            drop(players);
            return removed.then_some(PlayerEvent::Left(name));
        }
        None
    }

    /// Number of online players.
    #[must_use]
    pub fn count(&self) -> usize {
        self.lock().len()
    }

    /// Online player names, sorted for determinism.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = self.lock().iter().cloned().collect();
        names.sort();
        names
    }

    /// Forget all players; used when the server process exits.
    pub fn clear(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> MutexGuard<'_, HashSet<String>> {
        self.players.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn capture<'t>(regex: &Regex, line: &'t str) -> Option<&'t str> {
    regex
        .captures(line)
        .and_then(|captures| captures.name("player"))
        .map(|matched| matched.as_str())
}

#[cfg(test)]
mod tests {
    use super::{PlayerEvent, PlayerTracker};
    use crate::config::PlayerRegexes;

    fn default_tracker() -> PlayerTracker {
        let regexes = PlayerRegexes::new(None, None)
            .unwrap_or_else(|err| panic!("default regexes should compile: {err}"));
        PlayerTracker::new(regexes)
    }

    fn tracker_with(join: &str, leave: &str) -> PlayerTracker {
        let regexes = PlayerRegexes::new(Some(join), Some(leave))
            .unwrap_or_else(|err| panic!("custom regexes should compile: {err}"));
        PlayerTracker::new(regexes)
    }

    #[test]
    fn join_and_leave_with_timestamp_prefix() {
        let tracker = default_tracker();
        let cases = [
            (
                "[12:34:56] [Server thread/INFO]: alice joined the game",
                Some(PlayerEvent::Joined("alice".to_string())),
            ),
            (
                "[12:35:01] [Server thread/INFO]: alice left the game",
                Some(PlayerEvent::Left("alice".to_string())),
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(
                tracker.parse_line(line),
                expected,
                "parsing {line:?} with default regexes"
            );
        }
    }

    #[test]
    fn ignores_chat_and_unrelated_lines() {
        let tracker = default_tracker();
        let cases = [
            "<alice> hello",
            "[12:34:56] [Server thread/INFO]: alice joined the server",
            "Stopping the server",
            "[12:34:56] [Server thread/INFO]: Starting minecraft server",
            "",
        ];
        for line in cases {
            assert_eq!(
                tracker.parse_line(line),
                None,
                "line {line:?} should not match any event"
            );
        }
        assert_eq!(tracker.count(), 0, "no player should have been added");
    }

    #[test]
    fn repeated_join_is_no_change() {
        let tracker = default_tracker();
        let line = "[12:34:56] [Server thread/INFO]: alice joined the game";
        assert_eq!(
            tracker.parse_line(line),
            Some(PlayerEvent::Joined("alice".to_string())),
            "first join is a change"
        );
        assert_eq!(
            tracker.parse_line(line),
            None,
            "repeated join should be a no-op"
        );
        assert_eq!(tracker.count(), 1, "still exactly one player");
    }

    #[test]
    fn leave_of_absent_player_is_no_change() {
        let tracker = default_tracker();
        let line = "[12:34:56] [Server thread/INFO]: bob left the game";
        assert_eq!(
            tracker.parse_line(line),
            None,
            "leave of an absent player should be a no-op"
        );
        assert_eq!(tracker.count(), 0, "player count should stay zero");
    }

    #[test]
    fn list_is_sorted_and_clear_empties() {
        let tracker = default_tracker();
        for (line, name) in [
            (
                "[12:34:56] [Server thread/INFO]: bob joined the game",
                "bob",
            ),
            (
                "[12:34:57] [Server thread/INFO]: alice joined the game",
                "alice",
            ),
        ] {
            tracker.parse_line(line);
            assert!(
                tracker.list().contains(&name.to_string()),
                "{name} should be tracked after {line:?}"
            );
        }
        assert_eq!(
            tracker.list(),
            vec!["alice".to_string(), "bob".to_string()],
            "list should be sorted"
        );
        tracker.clear();
        assert!(
            tracker.list().is_empty(),
            "list should be empty after clear"
        );
        assert_eq!(tracker.count(), 0, "count should be zero after clear");
    }

    #[test]
    fn custom_regexes_can_match_bare_lines() {
        let tracker = tracker_with(
            r"^(?P<player>\S+) joined the game",
            r"^(?P<player>\S+) left the game",
        );
        let cases = [
            (
                "alice joined the game",
                Some(PlayerEvent::Joined("alice".to_string())),
            ),
            (
                "alice left the game",
                Some(PlayerEvent::Left("alice".to_string())),
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(
                tracker.parse_line(line),
                expected,
                "parsing {line:?} with custom regexes"
            );
        }
    }

    #[test]
    fn names_with_surrounding_punctuation_are_captured_verbatim() {
        let tracker = tracker_with(
            r"^\S+ \S+ \S+ (?P<player>\S+) joined the game",
            r"^\S+ \S+ \S+ (?P<player>\S+) left the game",
        );
        tracker.parse_line("[00:00:00] [Server thread/INFO]: [Admin] joined the game");
        assert_eq!(
            tracker.list(),
            vec!["[Admin]".to_string()],
            "the raw capture should be stored"
        );
    }
}
