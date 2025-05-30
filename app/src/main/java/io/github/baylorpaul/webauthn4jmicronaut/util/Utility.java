package io.github.baylorpaul.webauthn4jmicronaut.util;

public class Utility {

	public static boolean isEmptyTrimmed(String s) {
		return s == null || s.trim().isEmpty();
	}

	public static String unNull(String s) {
		return s == null ? "" : s;
	}

	/**
	 * Limit text to a maximum number of characters
	 * @param text the text to limit
	 * @param limit the maximum number of characters including trailing text, or -1 for unlimited characters
	 * @param trailingText trailing text to include at the end of the string when truncating the text, such as ellipsis,
	 *            when the text length exceeds the limit
	 * @return the text limited to the specified number of characters including the trailing text
	 */
	public static String charLimit(String text, int limit, String trailingText) {
		String str = unNull(text);
		String strTrailing = unNull(trailingText);
		if (limit >= 0 && str.length() > limit) {
			int maxTextLen = limit - strTrailing.length();
			maxTextLen = Math.max(0, maxTextLen);

			str = str.substring(0, maxTextLen);
			str += strTrailing;
		}
		return str;
	}
}
