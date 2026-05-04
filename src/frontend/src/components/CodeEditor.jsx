import { useRef, useEffect } from 'react';
import { EditorView } from '@codemirror/view';
import { EditorState, Compartment } from '@codemirror/state';
import { basicSetup } from 'codemirror';
import { javascript } from '@codemirror/lang-javascript';

const editableCompartment = new Compartment();

export default function CodeEditor({ value, onChange, disabled, height }) {
  const editorRef = useRef(null);
  const viewRef = useRef(null);

  useEffect(() => {
    const state = EditorState.create({
      doc: value,
      extensions: [
        basicSetup,
        javascript(),
        EditorView.lineWrapping,
        editableCompartment.of(EditorView.editable.of(!disabled)),
        EditorView.updateListener.of((update) => {
          if (update.docChanged && onChange) {
            const newValue = update.state.doc.toString();
            onChange(newValue);
          }
        }),
      ],
    });

    const view = new EditorView({
      state,
      parent: editorRef.current,
    });

    viewRef.current = view;

    return () => view.destroy();
    // eslint-disable-next-line
  }, []);

  useEffect(() => {
    if (viewRef.current) {
      const currentValue = viewRef.current.state.doc.toString();
      if (value !== currentValue) {
        viewRef.current.dispatch({
          changes: { from: 0, to: currentValue.length, insert: value || '' }
        });
      }
    }
  }, [value]);

  useEffect(() => {
    if (viewRef.current) {
      viewRef.current.dispatch({
        effects: editableCompartment.reconfigure(EditorView.editable.of(!disabled))
      });
    }
  }, [disabled]);

  return (
    <div
      ref={editorRef}
      style={{
        height: height,
        overflowY: 'auto',
        border: '1px solid #d9d9d9',
        borderRadius: '2px',
        opacity: disabled ? 0.6 : 1,
        cursor: disabled ? 'not-allowed' : 'auto'
      }}
    />
  );
};