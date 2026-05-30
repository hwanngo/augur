import React, { useEffect, useRef, useState } from 'react';

/**
 * Tracks "is this element open" + closes it when the user mousedown's outside the ref'd container.
 * Returns [open, setOpen, containerRef]. Shared by Dropdown and any popover.
 *
 * `extraRef` is an optional second element treated as "inside" — e.g. a menu that is
 * portaled to document.body and therefore lives outside the container in the DOM. Without
 * it, a mousedown on the portaled menu would be seen as "outside" and close it before the
 * click selects an option.
 */
const useOutsideClick = (
  extraRef?: React.RefObject<HTMLElement | null>,
): [
  boolean,
  React.Dispatch<React.SetStateAction<boolean>>,
  React.RefObject<HTMLDivElement | null>,
] => {
  const elementRef = useRef<HTMLDivElement>(null);
  const [showElement, setShowElement] = useState<boolean>(false);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (elementRef.current?.contains(target)) return;
      if (extraRef?.current?.contains(target)) return;
      setShowElement(false);
    };
    if (showElement) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showElement, extraRef]);

  return [showElement, setShowElement, elementRef];
};

export default useOutsideClick;
